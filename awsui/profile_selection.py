"""Reusable local AWS profile selection and creation workflow."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TextIO

from .aws_cli import AwsCliInfo
from .cli_console import CliConsole, safe_text
from .interactive import InputClosedError, read_line
from .interactive_selector import (
    SelectionOption,
    SelectorInputClosed,
    select_option,
    supports_arrow_selection,
)
from .models import Profile
from .profile_catalog import (
    ProfileCatalog,
    ProfileCatalogError,
    load_profile_catalog,
)
from .profile_creation import (
    ProfileCommandRunner,
    ProfileCreationCancelled,
    create_profile_interactively,
)


class ProfileSelectionCancelled(Exception):
    """Raised when profile selection is cancelled."""

    def __init__(self, *, input_closed: bool = False) -> None:
        self.input_closed = input_closed
        detail = "profile selection cancelled"
        if input_closed:
            detail += ": input closed"
        super().__init__(detail)


class ProfileWorkflowError(Exception):
    """Raised when profiles cannot be loaded for interactive selection."""


class ProfileChoiceKind(Enum):
    PROFILE = "profile"
    CREATE = "create"
    CANCEL = "cancel"


@dataclass(frozen=True, slots=True)
class ProfileChoice:
    kind: ProfileChoiceKind
    profile: str | None = None


def render_profiles(
    profiles: Sequence[Profile],
    *,
    current_profile: str | None,
    stdout: TextIO,
) -> None:
    """Render numbered local profiles and an optional current binding."""
    profile_names = {profile["name"] for profile in profiles}
    for index, profile in enumerate(profiles, start=1):
        details = [profile["kind"]]
        if profile.get("region"):
            details.append(profile["region"])
        detail_text = " · ".join(details)
        current_marker = " [current]" if profile["name"] == current_profile else ""
        print(
            f"  {index}. {profile['name']} ({detail_text}){current_marker}",
            file=stdout,
        )

    if current_profile is not None and current_profile not in profile_names:
        print("", file=stdout)
        print(
            f"Current binding {current_profile!r} was not found in local AWS profiles.",
            file=stdout,
        )


def prompt_profile_choice(
    profiles: Sequence[Profile],
    *,
    current_profile: str | None,
    allow_create: bool,
    stdin: TextIO,
    stdout: TextIO,
) -> ProfileChoice:
    """Return a typed existing-profile or create-new choice."""
    if supports_arrow_selection(stdin, stdout):
        return _prompt_profile_choice_with_arrows(
            profiles,
            current_profile=current_profile,
            allow_create=allow_create,
            stdin=stdin,
            stdout=stdout,
        )

    output = CliConsole(stdout)
    profiles_by_name = {profile["name"]: profile for profile in profiles}
    current_is_available = current_profile in profiles_by_name

    while True:
        if profiles:
            prompt = f"Profile [1-{len(profiles)}]"
        else:
            prompt = "Profile"
        if current_is_available:
            prompt += f" (Enter keeps {current_profile})"
        if allow_create:
            prompt += ", c to create"
        prompt += ", or q to cancel: "
        try:
            selection = read_line(prompt, stdin=stdin, stdout=stdout)
        except InputClosedError as exc:
            raise ProfileSelectionCancelled(input_closed=True) from exc

        choice = selection.strip()
        if choice.casefold() in {"q", "quit"}:
            raise ProfileSelectionCancelled()

        if allow_create and choice.casefold() in {"c", "create"}:
            return ProfileChoice(ProfileChoiceKind.CREATE)

        if not choice and current_is_available:
            return ProfileChoice(ProfileChoiceKind.PROFILE, current_profile)

        if choice.isdecimal():
            index = int(choice)
            if 1 <= index <= len(profiles):
                return ProfileChoice(
                    ProfileChoiceKind.PROFILE,
                    profiles[index - 1]["name"],
                )

        if choice in profiles_by_name:
            return ProfileChoice(ProfileChoiceKind.PROFILE, choice)

        accepted = "a listed number, an exact profile name"
        if allow_create:
            accepted += ", c to create"
        message = f"Invalid selection. Enter {accepted}, or q to cancel."
        output.print(
            safe_text(message, "awsui.warning"),
            plain=message,
        )


def select_or_create_profile(
    *,
    project: str,
    environment: str,
    current_profile: str | None,
    base_environment: Mapping[str, str],
    stdin: TextIO,
    stdout: TextIO,
    profiles_loader: Callable[[], list[Profile]] | None = None,
    command_runner: ProfileCommandRunner | None = None,
    cli_info_provider: Callable[[], AwsCliInfo | None] | None = None,
) -> Profile:
    """Select an existing profile or create one without leaving the workflow."""
    try:
        catalog = load_profile_catalog(profiles_loader)
    except ProfileCatalogError as exc:
        raise ProfileWorkflowError(str(exc)) from exc

    while True:
        if supports_arrow_selection(stdin, stdout):
            _render_missing_current_binding(
                catalog,
                current_profile=current_profile,
                stdout=stdout,
            )
        else:
            _render_catalog(catalog, current_profile=current_profile, stdout=stdout)
        choice = prompt_profile_choice(
            catalog.profiles,
            current_profile=current_profile,
            allow_create=True,
            stdin=stdin,
            stdout=stdout,
        )
        if choice.kind is ProfileChoiceKind.PROFILE:
            profile = catalog.get(choice.profile or "")
            if profile is not None:
                return profile
            continue
        if choice.kind is ProfileChoiceKind.CANCEL:
            raise ProfileSelectionCancelled()

        creation_kwargs = {}
        if command_runner is not None:
            creation_kwargs["command_runner"] = command_runner
        if cli_info_provider is not None:
            creation_kwargs["cli_info_provider"] = cli_info_provider
        try:
            created = create_profile_interactively(
                project=project,
                environment=environment,
                catalog=catalog,
                base_environment=base_environment,
                stdin=stdin,
                stdout=stdout,
                profiles_loader=profiles_loader,
                **creation_kwargs,
            )
        except ProfileCreationCancelled as exc:
            raise ProfileSelectionCancelled(input_closed=True) from exc
        if created is not None:
            return created


def _render_catalog(
    catalog: ProfileCatalog,
    *,
    current_profile: str | None,
    stdout: TextIO,
) -> None:
    print("Local AWS profiles:", file=stdout)
    if not catalog.profiles:
        print("  No local AWS profiles found.", file=stdout)
    render_profiles(
        catalog.profiles,
        current_profile=current_profile,
        stdout=stdout,
    )


def _prompt_profile_choice_with_arrows(
    profiles: Sequence[Profile],
    *,
    current_profile: str | None,
    allow_create: bool,
    stdin: TextIO,
    stdout: TextIO,
) -> ProfileChoice:
    options: list[SelectionOption[ProfileChoice]] = []
    for profile in profiles:
        detail_parts = [profile["kind"], profile.get("region") or "no region"]
        if profile["name"] == current_profile:
            detail_parts.append("current")
        options.append(
            SelectionOption(
                profile["name"],
                ProfileChoice(ProfileChoiceKind.PROFILE, profile["name"]),
                " · ".join(detail_parts),
            )
        )

    create_choice = ProfileChoice(ProfileChoiceKind.CREATE)
    if allow_create:
        options.append(
            SelectionOption(
                "Create new AWS profile…",
                create_choice,
                "Console Login, SSO, or access key",
                separator_before=True,
            )
        )
    cancel_choice = ProfileChoice(ProfileChoiceKind.CANCEL)
    options.append(
        SelectionOption(
            "Cancel",
            cancel_choice,
            separator_before=not allow_create,
        )
    )

    profile_default = next(
        (
            option.value
            for option in options
            if option.value.profile == current_profile
            and option.value.kind is ProfileChoiceKind.PROFILE
        ),
        None,
    )
    default = profile_default or (
        options[0].value
        if profiles
        else create_choice
        if allow_create
        else cancel_choice
    )
    try:
        return select_option(
            "Local AWS profile",
            options,
            default=default,
            stdin=stdin,
            stdout=stdout,
        )
    except SelectorInputClosed as exc:
        raise ProfileSelectionCancelled(input_closed=True) from exc


def _render_missing_current_binding(
    catalog: ProfileCatalog,
    *,
    current_profile: str | None,
    stdout: TextIO,
) -> None:
    if current_profile is None or catalog.get(current_profile) is not None:
        return
    message = f"Current binding {current_profile!r} was not found locally."
    CliConsole(stdout).print(safe_text(f"! {message}", "awsui.warning"), plain=message)
