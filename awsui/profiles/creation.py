"""Core AWS CLI profile creation operations."""

from collections.abc import Callable, Mapping
from enum import Enum
import os
from typing import TextIO

from ..aws_cli import run_aws_interactive
from ..runtime_environment import sanitize_credential_environment
from .catalog import ProfileCatalogError, load_profile_catalog
from .models import Profile


class ProfileCreationMethod(Enum):
    CONSOLE = "console"
    SSO = "sso"
    ACCESS_KEY = "access-key"


class ProfileCreationError(Exception):
    """Raised when the official AWS CLI cannot create a requested profile."""


class ProfileCreationCommandCancelled(ProfileCreationError):
    """Raised when the official AWS CLI profile command is cancelled."""


ProfileCommandRunner = Callable[..., int]


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
    return created


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
