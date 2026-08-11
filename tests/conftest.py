"""Pytest configuration and fixtures."""

import os

import pytest


@pytest.fixture(autouse=True)
def isolated_cli_settings(tmp_path, monkeypatch):
    """Keep CLI preference tests away from the real user settings file."""
    settings_path = tmp_path / ".config" / "awsui" / "settings.json"
    monkeypatch.setattr(
        "awsui.cli.get_default_settings_path",
        lambda: settings_path,
    )
    return settings_path


@pytest.fixture
def temp_aws_config(tmp_path):
    """Create a temporary AWS config file."""
    config_dir = tmp_path / ".aws"
    config_dir.mkdir()
    config_file = config_dir / "config"
    return config_file


@pytest.fixture
def temp_aws_credentials(tmp_path):
    """Create a temporary AWS credentials file."""
    config_dir = tmp_path / ".aws"
    config_dir.mkdir(exist_ok=True)
    credentials_file = config_dir / "credentials"
    return credentials_file


@pytest.fixture
def sample_sso_config():
    """Return sample SSO configuration content."""
    return """[sso-session corp]
sso_start_url = https://example.awsapps.com/start
sso_region = ap-northeast-1

[profile test-sso]
sso_session = corp
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
region = ap-northeast-1
output = json
"""


@pytest.fixture
def sample_assume_config():
    """Return sample assume role configuration content."""
    return """[profile base]
region = us-east-1

[profile test-assume]
source_profile = base
role_arn = arn:aws:iam::222222222222:role/MyRole
region = us-west-2
"""


@pytest.fixture
def mock_env(monkeypatch):
    """Provide a clean environment for testing."""
    # Clear AWS-related environment variables
    for key in list(os.environ.keys()):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)

    return monkeypatch
