"""Profile-aware AWS authentication and reauthentication strategy."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TextIO

from .aws_cli import console_login, get_caller_identity, sso_login
from .models import Profile
from .profile_catalog import ProfileCatalog, load_profile_catalog


class ReauthenticationMethod(Enum):
    SSO = "sso"
    CONSOLE = "console"


@dataclass(frozen=True, slots=True)
class ReauthenticationPlan:
    method: ReauthenticationMethod
    profile: str


class ProfileAuthenticationError(Exception):
    """Raised when profile authentication configuration cannot be resolved."""


def resolve_reauthentication_plan(
    profile_name: str,
    catalog: ProfileCatalog,
) -> ReauthenticationPlan | None:
    """Resolve the interactive login behind a target profile, if any."""
    visited: list[str] = []
    current_name = profile_name
    while True:
        if current_name in visited:
            chain = " -> ".join((*visited, current_name))
            raise ProfileAuthenticationError(f"profile source cycle detected: {chain}")
        visited.append(current_name)

        profile = catalog.get(current_name)
        if profile is None:
            raise ProfileAuthenticationError(
                f"local AWS profile {current_name!r} was not found"
            )
        if profile["kind"] == "sso":
            return ReauthenticationPlan(ReauthenticationMethod.SSO, current_name)
        if profile["kind"] == "login":
            return ReauthenticationPlan(
                ReauthenticationMethod.CONSOLE,
                current_name,
            )
        if profile["kind"] != "assume":
            return None

        source_profile = profile.get("source_profile")
        if source_profile is None:
            return None
        current_name = source_profile


def authenticate_profile(
    profile_name: str,
    *,
    environment: Mapping[str, str] | None = None,
    login_output: TextIO | None = None,
    cancel_check: Callable[[], bool] | None = None,
    catalog: ProfileCatalog | None = None,
) -> Mapping[str, object] | None:
    """Get identity, using only the login method configured for the profile."""
    if cancel_check and cancel_check():
        return None
    identity = _caller_identity(profile_name, environment)
    if identity is not None:
        return identity
    if cancel_check and cancel_check():
        return None

    selected_catalog = load_profile_catalog() if catalog is None else catalog
    if not reauthenticate_profile(
        profile_name,
        catalog=selected_catalog,
        environment=environment,
        login_output=login_output,
        cancel_check=cancel_check,
    ):
        return None
    if cancel_check and cancel_check():
        return None
    return _caller_identity(profile_name, environment)


def reauthenticate_profile(
    profile_name: str,
    *,
    catalog: ProfileCatalog | None = None,
    environment: Mapping[str, str] | None = None,
    login_output: TextIO | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> bool:
    """Run the configured interactive login for a profile or its source."""
    selected_catalog = load_profile_catalog() if catalog is None else catalog
    plan = resolve_reauthentication_plan(profile_name, selected_catalog)
    if plan is None:
        return False
    login = sso_login if plan.method is ReauthenticationMethod.SSO else console_login
    return login(
        plan.profile,
        cancel_check=cancel_check,
        environment=environment,
        login_output=login_output,
    )


def _caller_identity(
    profile: str,
    environment: Mapping[str, str] | None,
) -> Mapping[str, object] | None:
    if environment is None:
        return get_caller_identity(profile)
    return get_caller_identity(profile, environment=environment)


def describe_authentication(profile: Profile) -> str:
    """Return a human-readable authentication label for profile lists."""
    labels = {
        "sso": "sso",
        "login": "console login",
        "assume": "assume role",
        "process": "credential process",
        "basic": "access key/basic",
    }
    return labels[profile["kind"]]
