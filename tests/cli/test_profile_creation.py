"""Tests for official AWS CLI profile creation workflows."""

from io import StringIO
from unittest.mock import Mock

from awsui.aws_cli import AwsCliInfo
from awsui.cli.profile_creation import create_profile_interactively
from awsui.profiles.catalog import ProfileCatalog


def profile(name, kind="sso"):
    return {
        "name": name,
        "kind": kind,
        "account": None,
        "role": None,
        "region": "ap-northeast-1",
        "session": "company" if kind == "sso" else None,
        "source": "/home/user/.aws/config",
    }


def cli_info(version=(2, 34, 15)):
    return AwsCliInfo(version=version, raw=f"aws-cli/{'.'.join(map(str, version))}")


def create_with(command_input, *, created_kind="sso", base_environment=None):
    runner = Mock(return_value=0)
    created = profile("payment-service-dev", created_kind)
    result = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        base_environment=base_environment or {},
        stdin=StringIO(command_input),
        stdout=StringIO(),
        profiles_loader=lambda: [created],
        command_runner=runner,
        cli_info_provider=lambda: cli_info(),
    )
    return result, runner


def test_creates_console_login_profile_and_selects_it():
    created, runner = create_with("2\n\n", created_kind="login")

    assert created["name"] == "payment-service-dev"
    assert created["kind"] == "login"
    assert runner.call_args.args[0] == [
        "aws",
        "login",
        "--profile",
        "payment-service-dev",
    ]


def test_creates_sso_profile_with_official_wizard():
    _created, runner = create_with("1\n\n")

    assert runner.call_args.args[0] == [
        "aws",
        "configure",
        "sso",
        "--profile",
        "payment-service-dev",
    ]


def test_access_key_requires_confirmation_and_sanitizes_environment():
    _created, runner = create_with(
        "3\n\ny\n",
        created_kind="basic",
        base_environment={
            "PATH": "/bin",
            "AWS_ACCESS_KEY_ID": "must-not-leak",
            "AWS_SECRET_ACCESS_KEY": "must-not-leak",
            "AWS_CONFIG_FILE": "/custom/config",
        },
    )

    assert runner.call_args.args[0] == [
        "aws",
        "configure",
        "--profile",
        "payment-service-dev",
    ]
    environment = runner.call_args.kwargs["environment"]
    assert environment["PATH"] == "/bin"
    assert environment["AWS_CONFIG_FILE"] == "/custom/config"
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment


def test_access_key_default_no_does_not_launch_command():
    runner = Mock()
    output = StringIO()

    result = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        stdin=StringIO("3\n\n\n"),
        stdout=output,
        command_runner=runner,
        cli_info_provider=lambda: cli_info(),
    )

    assert result is None
    runner.assert_not_called()
    assert "Long-term access keys are not recommended" in output.getvalue()


def test_console_login_is_disabled_on_old_aws_cli():
    output = StringIO()

    result = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        stdin=StringIO("2\nb\n"),
        stdout=output,
        cli_info_provider=lambda: cli_info((2, 31, 0)),
    )

    assert result is None
    assert "requires AWS CLI 2.32 or newer" in output.getvalue()


def test_existing_default_name_must_be_replaced():
    runner = Mock(return_value=0)
    existing = profile("payment-service-dev")
    replacement = profile("my-new-profile")

    result = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([existing]),
        stdin=StringIO("1\n\nmy-new-profile\n"),
        stdout=StringIO(),
        profiles_loader=lambda: [existing, replacement],
        command_runner=runner,
        cli_info_provider=lambda: cli_info(),
    )

    assert result["name"] == "my-new-profile"
    assert runner.call_args.args[0][-1] == "my-new-profile"


def test_failed_or_missing_creation_returns_to_caller_without_profile():
    failed_runner = Mock(return_value=7)
    failed = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        stdin=StringIO("1\n\n"),
        stdout=StringIO(),
        command_runner=failed_runner,
        cli_info_provider=lambda: cli_info(),
    )
    assert failed is None

    missing = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        stdin=StringIO("1\n\n"),
        stdout=StringIO(),
        profiles_loader=lambda: [],
        command_runner=Mock(return_value=0),
        cli_info_provider=lambda: cli_info(),
    )
    assert missing is None
