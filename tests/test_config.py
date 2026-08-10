"""Tests for config parsing."""

import os
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from awsui.config import parse_profiles


@pytest.fixture(autouse=True)
def isolate_aws_config_files(tmp_path, monkeypatch):
    """Prevent config tests from reading the developer's real AWS files."""
    config_path = tmp_path / "config"
    credentials_path = tmp_path / "credentials"
    config_path.write_text("")
    credentials_path.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_path))


def test_parse_sso_profile():
    """Test parsing SSO profile from config."""
    config_content = """[sso-session corp]
sso_start_url = https://example.awsapps.com/start
sso_region = ap-northeast-1

[profile test-sso]
sso_session = corp
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
region = ap-northeast-1
output = json
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Set environment variable to use test config
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        assert len(profiles) >= 1
        sso_profile = next((p for p in profiles if p["name"] == "test-sso"), None)
        assert sso_profile is not None
        assert sso_profile["kind"] == "sso"
        assert sso_profile["account"] == "111111111111"
        assert sso_profile["role"] == "AdministratorAccess"
        assert sso_profile["region"] == "ap-northeast-1"
        assert sso_profile["session"] == "corp"

    finally:
        # Restore environment
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        # Clean up temp file
        Path(config_path).unlink(missing_ok=True)


def test_parse_assume_role_profile():
    """Test parsing assume role profile."""
    config_content = """[profile base]
region = us-east-1

[profile test-assume]
source_profile = base
role_arn = arn:aws:iam::222222222222:role/MyRole
region = us-west-2
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        assume_profile = next((p for p in profiles if p["name"] == "test-assume"), None)
        assert assume_profile is not None
        assert assume_profile["kind"] == "assume"
        assert assume_profile["account"] == "222222222222"
        assert assume_profile["role"] == "MyRole"
        assert assume_profile["region"] == "us-west-2"

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_parse_empty_config():
    """Test parsing empty config file."""
    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write("")
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()
        # Should return empty list or only profiles from credentials file
        assert isinstance(profiles, list)

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_parse_legacy_sso_profile():
    """Test parsing legacy SSO profile without sso-session."""
    config_content = """[profile legacy-sso]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 333333333333
sso_role_name = ViewOnlyAccess
region = us-east-1
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        sso_profile = next((p for p in profiles if p["name"] == "legacy-sso"), None)
        assert sso_profile is not None
        assert sso_profile["kind"] == "sso"
        assert sso_profile["account"] == "333333333333"
        assert sso_profile["role"] == "ViewOnlyAccess"
        assert sso_profile["session"] is None  # No session for legacy SSO

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_parse_basic_profile():
    """Test parsing basic profile without SSO or assume role."""
    config_content = """[profile basic]
region = ap-northeast-1
output = json
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        basic_profile = next((p for p in profiles if p["name"] == "basic"), None)
        assert basic_profile is not None
        assert basic_profile["kind"] == "basic"
        assert basic_profile["region"] == "ap-northeast-1"
        assert basic_profile["account"] is None
        assert basic_profile["role"] is None

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_parse_default_profile():
    """Test parsing default profile (without 'profile ' prefix)."""
    config_content = """[default]
region = us-west-2
output = json
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        default_profile = next((p for p in profiles if p["name"] == "default"), None)
        assert default_profile is not None
        assert default_profile["region"] == "us-west-2"

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_parse_credentials_file():
    """Test parsing credentials file for basic profiles."""
    creds_content = """[creds-profile]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

    with NamedTemporaryFile(mode="w", suffix=".credentials", delete=False) as f:
        f.write(creds_content)
        creds_path = f.name

    # Create empty config to avoid conflicts
    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write("")
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        original_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = creds_path

        profiles = parse_profiles()

        creds_profile = next(
            (p for p in profiles if p["name"] == "creds-profile"), None
        )
        assert creds_profile is not None
        assert creds_profile["kind"] == "basic"
        assert creds_profile["source"] == creds_path

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        if original_creds:
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = original_creds
        elif "AWS_SHARED_CREDENTIALS_FILE" in os.environ:
            del os.environ["AWS_SHARED_CREDENTIALS_FILE"]

        Path(config_path).unlink(missing_ok=True)
        Path(creds_path).unlink(missing_ok=True)


def test_parse_mixed_profiles():
    """Test parsing mix of SSO, assume, and basic profiles."""
    config_content = """[sso-session company]
sso_start_url = https://company.awsapps.com/start
sso_region = us-east-1

[profile sso-profile]
sso_session = company
sso_account_id = 111111111111
sso_role_name = Admin
region = us-east-1

[profile base]
region = us-west-2

[profile assume-profile]
source_profile = base
role_arn = arn:aws:iam::222222222222:role/CrossAccountRole
region = us-west-2

[profile basic-profile]
region = eu-west-1
output = json
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        # Should have 4 profiles (sso-session is skipped)
        assert len(profiles) == 4

        sso = next((p for p in profiles if p["name"] == "sso-profile"), None)
        assert sso and sso["kind"] == "sso"

        assume = next((p for p in profiles if p["name"] == "assume-profile"), None)
        assert assume and assume["kind"] == "assume"

        basic = next((p for p in profiles if p["name"] == "basic-profile"), None)
        assert basic and basic["kind"] == "basic"

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_sso_session_sections_skipped():
    """Test that sso-session sections are properly skipped."""
    config_content = """[sso-session test]
sso_start_url = https://test.awsapps.com/start
sso_region = us-east-1

[sso-session another]
sso_start_url = https://another.awsapps.com/start
sso_region = eu-west-1

[profile actual-profile]
sso_session = test
sso_account_id = 123456789012
sso_role_name = Admin
region = us-east-1
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        # Should only have 1 profile, sso-session sections excluded
        assert len(profiles) == 1
        assert profiles[0]["name"] == "actual-profile"

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_role_arn_parsing():
    """Test correct parsing of role ARN for account and role name."""
    config_content = """[profile test-assume]
source_profile = base
role_arn = arn:aws:iam::999888777666:role/MyCustomRole
region = us-east-1
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path

        profiles = parse_profiles()

        profile = profiles[0]
        assert profile["account"] == "999888777666"
        assert profile["role"] == "MyCustomRole"

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        Path(config_path).unlink(missing_ok=True)


def test_nonexistent_files():
    """Test behavior when config and credentials files don't exist."""
    # Set paths to nonexistent files
    original_config = os.environ.get("AWS_CONFIG_FILE")
    original_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")

    try:
        os.environ["AWS_CONFIG_FILE"] = "/tmp/nonexistent_config_12345.conf"
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/tmp/nonexistent_creds_12345.conf"

        profiles = parse_profiles()
        assert profiles == []

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        if original_creds:
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = original_creds
        elif "AWS_SHARED_CREDENTIALS_FILE" in os.environ:
            del os.environ["AWS_SHARED_CREDENTIALS_FILE"]


def test_static_credentials_take_precedence_over_config_authentication():
    """Static keys prevent an incorrect SSO reauthentication fallback."""
    config_content = """[profile shared-name]
sso_session = test
sso_account_id = 111111111111
sso_role_name = Admin
region = us-east-1
"""

    creds_content = """[shared-name]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

    with NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    with NamedTemporaryFile(mode="w", suffix=".credentials", delete=False) as f:
        f.write(creds_content)
        creds_path = f.name

    try:
        original_config = os.environ.get("AWS_CONFIG_FILE")
        original_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = creds_path

        profiles = parse_profiles()

        # One merged profile reflects the credential provider AWS CLI will use.
        assert len(profiles) == 1
        assert profiles[0]["kind"] == "basic"
        assert profiles[0]["source"] == creds_path

    finally:
        if original_config:
            os.environ["AWS_CONFIG_FILE"] = original_config
        elif "AWS_CONFIG_FILE" in os.environ:
            del os.environ["AWS_CONFIG_FILE"]

        if original_creds:
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = original_creds
        elif "AWS_SHARED_CREDENTIALS_FILE" in os.environ:
            del os.environ["AWS_SHARED_CREDENTIALS_FILE"]

        Path(config_path).unlink(missing_ok=True)
        Path(creds_path).unlink(missing_ok=True)


def test_parse_console_login_profile():
    config_path = Path(os.environ["AWS_CONFIG_FILE"])
    config_path.write_text(
        """[profile console-dev]
login_session = arn:aws:iam::111111111111:user/developer
region = ap-northeast-1
""",
        encoding="utf-8",
    )

    profiles = parse_profiles()

    assert profiles[0]["kind"] == "login"
    assert profiles[0]["login_session"].endswith(":user/developer")


def test_parse_credential_process_profile():
    config_path = Path(os.environ["AWS_CONFIG_FILE"])
    config_path.write_text(
        """[profile external]
credential_process = /usr/local/bin/get-credentials
region = us-east-1
""",
        encoding="utf-8",
    )

    profiles = parse_profiles()

    assert profiles[0]["kind"] == "process"
    assert profiles[0]["credential_process"] == "/usr/local/bin/get-credentials"


def test_parse_assume_role_with_credential_source():
    config_path = Path(os.environ["AWS_CONFIG_FILE"])
    config_path.write_text(
        """[profile workload]
role_arn = arn:aws:iam::222222222222:role/Deploy
credential_source = Ec2InstanceMetadata
region = us-west-2
""",
        encoding="utf-8",
    )

    profiles = parse_profiles()

    assert profiles[0]["kind"] == "assume"
    assert profiles[0]["credential_source"] == "Ec2InstanceMetadata"
    assert profiles[0]["account"] == "222222222222"
