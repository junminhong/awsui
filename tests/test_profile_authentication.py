"""Tests for profile-aware authentication strategy."""

from unittest.mock import patch

import pytest

from awsui.profile_authentication import (
    ProfileAuthenticationError,
    ReauthenticationMethod,
    ReauthenticationPlan,
    authenticate_profile,
    resolve_reauthentication_plan,
)
from awsui.profile_catalog import ProfileCatalog


def profile(name, kind, **fields):
    result = {
        "name": name,
        "kind": kind,
        "account": None,
        "role": None,
        "region": "ap-northeast-1",
        "session": None,
        "source": "/home/user/.aws/config",
    }
    result.update(fields)
    return result


def catalog(*profiles):
    return ProfileCatalog.from_profiles(profiles)


def test_resolves_direct_sso_and_console_login():
    profiles = catalog(
        profile("company-sso", "sso"),
        profile("console", "login"),
    )

    assert resolve_reauthentication_plan("company-sso", profiles) == (
        ReauthenticationPlan(ReauthenticationMethod.SSO, "company-sso")
    )
    assert resolve_reauthentication_plan("console", profiles) == (
        ReauthenticationPlan(ReauthenticationMethod.CONSOLE, "console")
    )


def test_assume_role_follows_nested_source_profile():
    profiles = catalog(
        profile("target", "assume", source_profile="middle"),
        profile("middle", "assume", source_profile="workforce"),
        profile("workforce", "sso"),
    )

    assert resolve_reauthentication_plan("target", profiles) == (
        ReauthenticationPlan(ReauthenticationMethod.SSO, "workforce")
    )


@pytest.mark.parametrize("kind", ["basic", "process"])
def test_noninteractive_profiles_have_no_login_fallback(kind):
    assert (
        resolve_reauthentication_plan("target", catalog(profile("target", kind)))
        is None
    )


def test_assume_role_with_credential_source_has_no_interactive_fallback():
    profiles = catalog(
        profile("target", "assume", credential_source="Ec2InstanceMetadata")
    )

    assert resolve_reauthentication_plan("target", profiles) is None


def test_source_cycle_and_missing_profile_are_explicit_errors():
    cyclic = catalog(
        profile("one", "assume", source_profile="two"),
        profile("two", "assume", source_profile="one"),
    )
    with pytest.raises(ProfileAuthenticationError, match="one -> two -> one"):
        resolve_reauthentication_plan("one", cyclic)

    with pytest.raises(ProfileAuthenticationError, match="was not found"):
        resolve_reauthentication_plan("missing", cyclic)


@patch("awsui.profile_authentication.sso_login", return_value=True)
@patch("awsui.profile_authentication.get_caller_identity")
def test_sso_login_retries_target_identity(mock_identity, mock_login):
    environment = {"AWS_PROFILE": "target"}
    mock_identity.side_effect = [None, {"Account": "999999999999"}]
    profiles = catalog(
        profile("target", "assume", source_profile="source"),
        profile("source", "sso"),
    )

    identity = authenticate_profile(
        "target",
        environment=environment,
        catalog=profiles,
    )

    assert identity == {"Account": "999999999999"}
    assert mock_identity.call_count == 2
    mock_login.assert_called_once_with(
        "source",
        cancel_check=None,
        environment=environment,
        login_output=None,
    )


@patch("awsui.profile_authentication.console_login", return_value=True)
@patch("awsui.profile_authentication.get_caller_identity")
def test_console_login_uses_console_command(mock_identity, mock_login):
    mock_identity.side_effect = [None, {"Account": "111111111111"}]

    identity = authenticate_profile(
        "console",
        catalog=catalog(profile("console", "login")),
    )

    assert identity == {"Account": "111111111111"}
    mock_login.assert_called_once_with(
        "console",
        cancel_check=None,
        environment=None,
        login_output=None,
    )


@patch("awsui.profile_authentication.console_login")
@patch("awsui.profile_authentication.sso_login")
@patch("awsui.profile_authentication.get_caller_identity", return_value=None)
def test_basic_profile_fails_without_wrong_login(
    _mock_identity,
    mock_sso,
    mock_console,
):
    assert (
        authenticate_profile(
            "basic",
            catalog=catalog(profile("basic", "basic")),
        )
        is None
    )
    mock_sso.assert_not_called()
    mock_console.assert_not_called()
