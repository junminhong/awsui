"""Configuration file parsing and discovery."""

import os
from pathlib import Path
from configparser import ConfigParser
from typing import List
from .models import Profile


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


def parse_profiles() -> List[Profile]:
    """
    Parse AWS profiles from config and credentials files.

    Returns a list of Profile objects.
    """
    config_file, credentials_file = get_config_paths()
    profiles: List[Profile] = []

    # Parse config file
    if config_file.exists():
        config = ConfigParser()
        config.read(config_file)

        for section in config.sections():
            # Skip sso-session sections
            if section.startswith("sso-session "):
                continue

            # Profile sections start with "profile "
            if section.startswith("profile "):
                profile_name = section[8:]  # Remove "profile " prefix
            else:
                # Default profile
                profile_name = section

            section_data = dict(config[section])

            # Determine profile kind
            if "sso_session" in section_data or "sso_start_url" in section_data:
                kind = "sso"
                session = section_data.get("sso_session")
                account = section_data.get("sso_account_id")
                role = section_data.get("sso_role_name")
            elif "source_profile" in section_data and "role_arn" in section_data:
                kind = "assume"
                session = None
                # Extract account from role_arn if present
                role_arn = section_data.get("role_arn", "")
                account = role_arn.split(":")[4] if ":" in role_arn else None
                role = role_arn.split("/")[-1] if "/" in role_arn else None
            else:
                kind = "basic"
                session = None
                account = None
                role = None

            profile = Profile(
                name=profile_name,
                kind=kind,
                account=account,
                role=role,
                region=section_data.get("region"),
                session=session,
                source=str(config_file),
            )
            profiles.append(profile)

    # Parse credentials file for basic profiles
    if credentials_file.exists():
        creds = ConfigParser()
        creds.read(credentials_file)

        for section in creds.sections():
            # Check if this profile already exists from config
            if any(p["name"] == section for p in profiles):
                continue

            # This is a basic credential profile
            profile = Profile(
                name=section,
                kind="basic",
                account=None,
                role=None,
                region=None,
                session=None,
                source=str(credentials_file),
            )
            profiles.append(profile)

    return profiles
