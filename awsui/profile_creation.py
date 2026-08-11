"""Interactive creation of AWS CLI profiles through official AWS commands."""

from collections.abc import Callable, Mapping
from enum import Enum
import os
from typing import TextIO

from rich.panel import Panel
from rich.text import Text

from .aws_cli import AwsCliInfo, get_aws_cli_info, run_aws_interactive
from .cli_console import CliConsole, safe_text
from .interactive import InputClosedError, prompt_value, prompt_yes_no, read_line
from .i18n import text
from .interactive_selector import (
    SelectionOption,
    SelectorInputClosed,
    select_option,
    supports_arrow_selection,
)
from .models import Profile
from .profile_catalog import ProfileCatalog, ProfileCatalogError, load_profile_catalog
from .runtime_environment import sanitize_credential_environment


class ProfileCreationMethod(Enum):
    CONSOLE = "console"
    SSO = "sso"
    ACCESS_KEY = "access-key"


class _CreationAction(Enum):
    BACK = "back"


class ProfileCreationCancelled(Exception):
    """Raised when profile creation input closes."""


class ProfileCreationError(Exception):
    """Raised when the official AWS CLI cannot create a requested profile."""


class ProfileCreationCommandCancelled(ProfileCreationError):
    """Raised when the official AWS CLI profile command is cancelled."""


ProfileCommandRunner = Callable[..., int]


def create_profile_interactively(
    *,
    project: str,
    environment: str,
    catalog: ProfileCatalog,
    base_environment: Mapping[str, str] | None = None,
    stdin: TextIO,
    stdout: TextIO,
    profiles_loader: Callable[[], list[Profile]] | None = None,
    command_runner: ProfileCommandRunner = run_aws_interactive,
    cli_info_provider: Callable[[], AwsCliInfo | None] = get_aws_cli_info,
) -> Profile | None:
    """Create, reload, and return a profile, or None when the user goes back."""
    output = CliConsole(stdout)
    try:
        method = _select_creation_method(
            stdin=stdin,
            stdout=stdout,
            cli_info=cli_info_provider(),
        )
        if method is None:
            return None

        default_name = f"{project}-{environment}"
        profile_name = _prompt_unique_name(
            default_name,
            catalog=catalog,
            stdin=stdin,
            stdout=stdout,
        )
        if method is ProfileCreationMethod.ACCESS_KEY:
            warning = text("cli_access_key_warning")
            output.print(
                Panel(
                    Text(warning, style="awsui.warning"),
                    title=Text(
                        f"! {text('cli_access_key_warning_title')}",
                        style="awsui.warning",
                    ),
                    border_style="yellow",
                    expand=False,
                ),
                plain=warning,
            )
            if not prompt_yes_no(
                text("cli_access_key_continue"),
                stdin=stdin,
                stdout=stdout,
            ):
                return None
    except InputClosedError as exc:
        raise ProfileCreationCancelled(
            "profile creation cancelled: input closed"
        ) from exc

    command = profile_creation_command(method, profile_name)
    running = f"{text('cli_running')}: {' '.join(command)}"
    output.print(
        Text.assemble(
            (f"● {text('cli_running')}  ", "awsui.title"),
            safe_text(" ".join(command), "awsui.value"),
        ),
        plain=running,
        flush=True,
    )
    try:
        return create_profile(
            method=method,
            profile_name=profile_name,
            base_environment=base_environment,
            output=stdout,
            profiles_loader=profiles_loader,
            command_runner=command_runner,
        )
    except ProfileCreationCommandCancelled:
        output.print(
            Text(f"! {text('cli_profile_creation_cancelled')}", style="awsui.warning"),
            plain=text("cli_profile_creation_cancelled"),
        )
        return None
    except ProfileCreationError as exc:
        failure = str(exc)
        output.print(
            Text.assemble(("✗ ", "awsui.error"), safe_text(failure, "awsui.error")),
            plain=failure,
        )
        return None


def create_profile(
    *,
    method: ProfileCreationMethod,
    profile_name: str,
    base_environment: Mapping[str, str] | None = None,
    output: TextIO | None = None,
    profiles_loader: Callable[[], list[Profile]] | None = None,
    command_runner: ProfileCommandRunner = run_aws_interactive,
) -> Profile:
    """Create one profile through the official AWS CLI and reload it."""
    command = profile_creation_command(method, profile_name)
    process_environment = sanitize_credential_environment(
        os.environ if base_environment is None else base_environment
    )
    exit_code = command_runner(
        command,
        environment=process_environment,
        output=output,
    )
    if exit_code == 130:
        raise ProfileCreationCommandCancelled("Profile creation cancelled.")
    if exit_code != 0:
        raise ProfileCreationError(
            f"Profile creation failed with exit code {exit_code}."
        )

    try:
        refreshed = load_profile_catalog(profiles_loader)
    except ProfileCatalogError as exc:
        raise ProfileCreationError(f"Unable to reload AWS profiles: {exc}") from exc
    created = refreshed.get(profile_name)
    if created is None:
        raise ProfileCreationError(
            f"AWS CLI completed, but profile {profile_name!r} was not found."
        )
    success = text("cli_profile_created", profile=profile_name)
    if output is not None:
        CliConsole(output).print(
            Text.assemble(
                ("✓ ", "awsui.success"),
                safe_text(success, "awsui.success"),
            ),
            plain=success,
        )
    return created


def _select_creation_method(
    *,
    stdin: TextIO,
    stdout: TextIO,
    cli_info: AwsCliInfo | None,
) -> ProfileCreationMethod | None:
    console_available = bool(cli_info and cli_info.supports_console_login)
    if supports_arrow_selection(stdin, stdout):
        options: list[SelectionOption[ProfileCreationMethod | _CreationAction]] = [
            SelectionOption(
                "IAM Identity Center (SSO)",
                ProfileCreationMethod.SSO,
                text("cli_recommended_orgs"),
            ),
            SelectionOption(
                text("cli_console_login"),
                ProfileCreationMethod.CONSOLE,
                text("cli_temporary_credentials"),
                disabled=None if console_available else text("cli_requires_cli"),
            ),
            SelectionOption(
                "Access key",
                ProfileCreationMethod.ACCESS_KEY,
                text("cli_not_recommended"),
            ),
            SelectionOption(
                text("cli_back"),
                _CreationAction.BACK,
                separator_before=True,
            ),
        ]
        try:
            selected = select_option(
                text("cli_auth_method"),
                options,
                default=ProfileCreationMethod.SSO,
                stdin=stdin,
                stdout=stdout,
            )
        except SelectorInputClosed as exc:
            raise InputClosedError("input closed") from exc
        if selected is _CreationAction.BACK:
            return None
        return selected

    output = CliConsole(stdout)
    while True:
        console_status = "" if console_available else f" [{text('cli_requires_cli')}]"
        print(f"{text('cli_auth_method')}:", file=stdout)
        print(f"  1. {text('cli_sso_recommended')}", file=stdout)
        print(f"  2. {text('cli_console_login')}{console_status}", file=stdout)
        print(f"  3. {text('cli_access_key_not_recommended')}", file=stdout)
        choice = (
            read_line(
                text("cli_auth_method_prompt"),
                stdin=stdin,
                stdout=stdout,
            )
            .strip()
            .casefold()
        )
        if choice in {"b", "back"}:
            return None
        if choice == "1":
            return ProfileCreationMethod.SSO
        if choice == "2":
            if console_available:
                return ProfileCreationMethod.CONSOLE
            message = text("cli_console_requires")
            output.print(safe_text(message, "awsui.warning"), plain=message)
            continue
        if choice == "3":
            return ProfileCreationMethod.ACCESS_KEY
        output.print(
            Text(text("cli_invalid_selection"), style="awsui.warning"),
            plain=text("cli_invalid_selection"),
        )


def _prompt_unique_name(
    default_name: str,
    *,
    catalog: ProfileCatalog,
    stdin: TextIO,
    stdout: TextIO,
) -> str:
    default: str | None = default_name
    output = CliConsole(stdout)
    while True:
        prompt = (
            text("cli_profile_name_prompt")
            if default is None
            else text("cli_profile_name_default_prompt", default=default)
        )
        name = prompt_value(
            prompt,
            default=default,
            stdin=stdin,
            stdout=stdout,
        )
        if catalog.get(name) is None:
            return name
        message = text("cli_profile_exists", profile=name)
        output.print(
            safe_text(message, "awsui.warning"),
            plain=message,
        )
        default = None


def profile_creation_command(
    method: ProfileCreationMethod,
    profile: str,
) -> list[str]:
    """Return the official AWS CLI command for a profile creation method."""
    if method is ProfileCreationMethod.CONSOLE:
        return ["aws", "login", "--profile", profile]
    if method is ProfileCreationMethod.SSO:
        return ["aws", "configure", "sso", "--profile", profile]
    return ["aws", "configure", "--profile", profile]
