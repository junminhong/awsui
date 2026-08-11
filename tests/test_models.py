"""Tests for data models."""

from awsui.models import Profile


def test_profile_sso():
    """Test SSO profile creation."""
    profile = Profile(
        name="test-sso",
        kind="sso",
        account="111111111111",
        role="AdministratorAccess",
        region="ap-northeast-1",
        session="corp",
        source="/path/to/config",
    )

    assert profile["name"] == "test-sso"
    assert profile["kind"] == "sso"
    assert profile["account"] == "111111111111"
    assert profile["role"] == "AdministratorAccess"
    assert profile["region"] == "ap-northeast-1"
    assert profile["session"] == "corp"


def test_profile_assume_role():
    """Test assume role profile creation."""
    profile = Profile(
        name="test-assume",
        kind="assume",
        account="222222222222",
        role="MyRole",
        region="us-west-2",
        session=None,
        source="/path/to/config",
    )

    assert profile["name"] == "test-assume"
    assert profile["kind"] == "assume"
    assert profile["account"] == "222222222222"
    assert profile["role"] == "MyRole"
    assert profile["session"] is None


def test_profile_basic():
    """Test basic profile creation."""
    profile = Profile(
        name="default",
        kind="basic",
        account=None,
        role=None,
        region=None,
        session=None,
        source="/path/to/credentials",
    )

    assert profile["name"] == "default"
    assert profile["kind"] == "basic"
    assert profile["account"] is None
    assert profile["role"] is None
