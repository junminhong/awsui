"""AWS profile configuration discovery and parsing."""

from configparser import ConfigParser
import os
from pathlib import Path
from typing import Literal

from .models import Profile, ProfileKind


def get_config_paths() -> tuple[Path, Path]:
    """
    Get AWS config and credentials file paths.

    Honors AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE environment variables.
    """
    home = Path.home()

    config_path = os.environ.get("AWS_CONFIG_FILE")
    if config_path:
        config_file = Path(config_path)
    else:
        config_file = home / ".aws" / "config"

    credentials_path = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    if credentials_path:
        credentials_file = Path(credentials_path)
    else:
        credentials_file = home / ".aws" / "credentials"

    return config_file, credentials_file


def parse_profiles() -> list[Profile]:
    """
    Parse AWS profiles from config and credentials files.

    Returns a list of Profile objects.
    """
    config_file, credentials_file = get_config_paths()
    config = _read_config(config_file)
    credentials = _read_config(credentials_file)
    credential_sections = set(credentials.sections())
    profiles: list[Profile] = []

    for section in config.sections():
        if section.startswith("sso-session "):
            continue
        profile_name = section[8:] if section.startswith("profile ") else section
        section_data = dict(config[section])
        credential_data = (
            dict(credentials[profile_name])
            if profile_name in credential_sections
            else {}
        )
        profiles.append(
            _profile_from_config(
                profile_name,
                section_data,
                credential_data=credential_data,
                config_file=config_file,
                credentials_file=credentials_file,
            )
        )

    configured_names = {profile["name"] for profile in profiles}
    for section in credentials.sections():
        if section in configured_names:
            continue
        profiles.append(
            Profile(
                name=section,
                kind="basic",
                account=None,
                role=None,
                region=None,
                session=None,
                source=str(credentials_file),
            )
        )

    return profiles


def _read_config(path: Path) -> ConfigParser:
    parser = ConfigParser()
    if path.exists():
        parser.read(path)
    return parser


def _profile_from_config(
    name: str,
    data: dict[str, str],
    *,
    credential_data: dict[str, str],
    config_file: Path,
    credentials_file: Path,
) -> Profile:
    static_credentials = _has_static_credentials(credential_data)
    kind = _profile_kind(data, static_credentials=static_credentials)
    role_arn = data.get("role_arn", "")
    profile = Profile(
        name=name,
        kind=kind,
        account=(
            data.get("sso_account_id")
            if kind == "sso"
            else _account_from_role_arn(role_arn)
        ),
        role=(data.get("sso_role_name") if kind == "sso" else _role_from_arn(role_arn)),
        region=data.get("region"),
        session=data.get("sso_session"),
        source=str(credentials_file if static_credentials else config_file),
    )
    _copy_optional(profile, data, "source_profile")
    _copy_optional(profile, data, "credential_source")
    _copy_optional(profile, data, "login_session")
    _copy_optional(profile, data, "credential_process")
    return profile


def _profile_kind(
    data: dict[str, str],
    *,
    static_credentials: bool,
) -> ProfileKind:
    if static_credentials:
        return "basic"
    if "sso_session" in data or "sso_start_url" in data:
        return "sso"
    if "login_session" in data:
        return "login"
    if "role_arn" in data:
        return "assume"
    if "credential_process" in data:
        return "process"
    return "basic"


def _has_static_credentials(data: dict[str, str]) -> bool:
    return "aws_access_key_id" in data and "aws_secret_access_key" in data


def _account_from_role_arn(role_arn: str) -> str | None:
    parts = role_arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _role_from_arn(role_arn: str) -> str | None:
    return role_arn.rsplit("/", 1)[-1] if "/" in role_arn else None


def _copy_optional(
    profile: Profile,
    data: dict[str, str],
    field: Literal[
        "source_profile",
        "credential_source",
        "login_session",
        "credential_process",
    ],
) -> None:
    value = data.get(field)
    if value is not None:
        profile[field] = value
