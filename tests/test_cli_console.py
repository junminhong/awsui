"""Tests for TTY-aware Rich command-line presentation."""

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from rich.panel import Panel

from awsui.aws_cli import AwsCliInfo
from awsui.bind_command import BindResult
from awsui.cli import main
from awsui.cli_console import CliConsole, safe_text
from awsui.cli_presenter import (
    render_account_mismatch_rich,
    render_bind_result_rich,
    render_doctor_report,
    render_doctor_report_rich,
    render_init_result_rich,
    render_launch_context_rich,
    render_verified_context_rich,
)
from awsui.context_engine import ResolvedContext
from awsui.context_runtime import VerifiedRuntime
from awsui.context_verification import AccountMismatchError, VerifiedContext
from awsui.doctor_command import DoctorCheck, DoctorReport
from awsui.init_command import InitResult, InitializedEnvironment
from awsui.profile_catalog import ProfileCatalog
from awsui.profile_creation import (
    ProfileCreationMethod,
    _select_creation_method,
    create_profile_interactively,
)
from awsui.profile_selection import (
    ProfileChoice,
    ProfileChoiceKind,
    select_or_create_profile,
)


class TerminalBuffer(StringIO):
    """String buffer that advertises terminal support to Rich."""

    def isatty(self) -> bool:
        return True


def _profile(name: str = "company-prod"):
    return {
        "name": name,
        "kind": "sso",
        "account": None,
        "role": None,
        "region": "ap-northeast-1",
        "session": "company",
        "source": "/home/user/.aws/config",
    }


def _verified_context(
    *,
    project: str = "payment-service",
    profile: str = "company-prod",
    principal_arn: str | None = None,
) -> VerifiedContext:
    resolved = ResolvedContext(
        project=project,
        environment="prod",
        expected_account="999999999999",
        region="ap-northeast-1",
        profile=profile,
        protected=True,
        project_config_path=Path("/project/.awsui.yaml"),
        bindings_path=Path("/home/user/.config/awsui/bindings.json"),
    )
    return VerifiedContext(
        resolved=resolved,
        actual_account="999999999999",
        principal_arn=principal_arn,
    )


def _render(renderable, *, environment=None) -> str:
    stream = StringIO()
    CliConsole(
        stream,
        environment={} if environment is None else environment,
        force_terminal=True,
        width=100,
    ).print(renderable)
    return stream.getvalue()


def test_non_terminal_uses_exact_plain_fallback():
    stream = StringIO()

    CliConsole(stream, force_terminal=False).print(
        Panel("enhanced"),
        plain="stable plain text",
    )

    assert stream.getvalue() == "stable plain text\n"


def test_tty_renders_structure_color_and_dynamic_markup_literally():
    output = _render(
        Panel(safe_text("project[prod] [bold red]literal[/]", "awsui.error"))
    )

    assert "\x1b[" in output
    assert "project[prod] [bold red]literal[/]" in output
    assert any(corner in output for corner in ("╭", "┌"))


def test_no_color_disables_all_ansi_control_sequences():
    output = _render(
        Panel(safe_text("PROTECTED", "awsui.protected")),
        environment={"NO_COLOR": "1"},
    )

    assert "\x1b[" not in output
    assert "PROTECTED" in output


@patch("awsui.profile_selection.select_option")
def test_profile_selection_uses_arrow_selector_with_current_default(
    mock_select,
    monkeypatch,
):
    monkeypatch.delenv("NO_COLOR", raising=False)
    stdin = TerminalBuffer()
    output = TerminalBuffer()
    mock_select.return_value = ProfileChoice(
        ProfileChoiceKind.PROFILE,
        "company-prod",
    )

    selected = select_or_create_profile(
        project="payment-service",
        environment="prod",
        current_profile="company-prod",
        base_environment={},
        stdin=stdin,
        stdout=output,
        profiles_loader=lambda: [_profile()],
    )

    assert selected["name"] == "company-prod"
    call = mock_select.call_args
    assert call.args[0] == "Local AWS profile"
    assert [option.label for option in call.args[1]] == [
        "company-prod",
        "Create new AWS profile…",
        "Cancel",
    ]
    assert "current" in call.args[1][0].detail
    assert call.kwargs["default"] == ProfileChoice(
        ProfileChoiceKind.PROFILE,
        "company-prod",
    )
    assert call.kwargs["stdin"] is stdin
    assert call.kwargs["stdout"] is output


def test_access_key_workflow_renders_warning_without_running_command():
    output = TerminalBuffer()
    runner = Mock()

    result = create_profile_interactively(
        project="payment-service",
        environment="dev",
        catalog=ProfileCatalog.from_profiles([]),
        stdin=StringIO("3\n\n\n"),
        stdout=output,
        command_runner=runner,
        cli_info_provider=lambda: AwsCliInfo((2, 34, 15), "aws-cli/2.34.15"),
    )

    assert result is None
    runner.assert_not_called()
    assert "Access key warning" in output.getvalue()
    assert "Long-term access keys are not recommended" in output.getvalue()


@patch("awsui.profile_creation.select_option")
def test_authentication_method_uses_arrow_selector_and_defaults_to_sso(
    mock_select,
):
    stdin = TerminalBuffer()
    stdout = TerminalBuffer()
    mock_select.return_value = ProfileCreationMethod.SSO

    selected = _select_creation_method(
        stdin=stdin,
        stdout=stdout,
        cli_info=AwsCliInfo((2, 34, 15), "aws-cli/2.34.15"),
    )

    assert selected is ProfileCreationMethod.SSO
    call = mock_select.call_args
    assert call.args[0] == "Authentication method"
    assert [option.label for option in call.args[1]] == [
        "IAM Identity Center (SSO)",
        "AWS Console Login",
        "Access key",
        "Back",
    ]
    assert call.kwargs["default"] is ProfileCreationMethod.SSO


@patch("awsui.profile_creation.select_option")
def test_authentication_selector_disables_console_login_on_old_cli(mock_select):
    mock_select.return_value = ProfileCreationMethod.SSO

    _select_creation_method(
        stdin=TerminalBuffer(),
        stdout=TerminalBuffer(),
        cli_info=AwsCliInfo((2, 31, 0), "aws-cli/2.31.0"),
    )

    console_choice = mock_select.call_args.args[1][1]
    assert console_choice.disabled == "requires AWS CLI ≥ 2.32"


def test_result_renderers_cover_context_launch_doctor_bind_and_init():
    verified = _verified_context()
    mismatch = AccountMismatchError(
        project="payment-service",
        environment="prod",
        profile="company-prod",
        expected_account="999999999999",
        actual_account="111111111111",
    )
    report = DoctorReport(
        checks=(
            DoctorCheck("AWS CLI v2", True, "available"),
            DoctorCheck(
                "Context prod",
                False,
                "not bound",
                "Run `awsui bind prod`.",
            ),
        )
    )
    bind = BindResult("payment-service", "prod", "company-prod", None, True)
    initialized = InitResult(
        project="payment-service",
        config_path=Path("/project/.awsui.yaml"),
        environments=(
            InitializedEnvironment(
                "prod",
                "company-prod",
                "999999999999",
                "ap-northeast-1",
                True,
            ),
        ),
    )

    assertions = (
        (render_verified_context_rich(verified), "AWS identity verified"),
        (render_launch_context_rich(verified, "terraform plan"), "terraform plan"),
        (render_account_mismatch_rich(mismatch), "AWS CONTEXT MISMATCH"),
        (render_doctor_report_rich(report), "Next steps"),
        (render_bind_result_rich(bind), "company-prod"),
        (render_init_result_rich(initialized), "Project initialized"),
    )
    for renderable, expected in assertions:
        output = _render(renderable)
        assert expected in output
        assert "\x1b[" in output

    plain_doctor = render_doctor_report(report)
    assert plain_doctor.endswith("Next steps\n  1. Run `awsui bind prod`.")


def test_verified_card_shows_role_only_from_sts_principal_arn():
    verified = _verified_context(
        principal_arn=(
            "arn:aws:sts::999999999999:assumed-role/ProductionAdmin/session-name"
        )
    )

    output = _render(render_verified_context_rich(verified))

    assert "Role" in output
    assert "ProductionAdmin" in output
    assert "session-name" not in output


@patch("awsui.cli.prepare_resolved_runtime")
@patch("awsui.cli.resolve_context")
def test_human_context_command_uses_rich_on_a_tty(
    mock_resolve,
    mock_prepare,
    monkeypatch,
):
    monkeypatch.delenv("NO_COLOR", raising=False)
    verified = _verified_context()
    mock_resolve.return_value = verified.resolved
    mock_prepare.return_value = VerifiedRuntime(verified=verified, environment={})
    stdout = TerminalBuffer()
    stderr = TerminalBuffer()

    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        exit_code = main(["context", "prod"])

    assert exit_code == 0
    assert any(corner in stdout.getvalue() for corner in ("╭", "┌"))
    assert "PROTECTED" in stdout.getvalue()
    assert "AWS identity verified" in stdout.getvalue()
    assert "\x1b[" in stdout.getvalue()
    assert "Authenticating and verifying" in stderr.getvalue()


@patch("awsui.cli.prepare_resolved_runtime")
@patch("awsui.cli.resolve_context")
def test_context_json_stays_unstyled_even_when_stdout_is_a_tty(
    mock_resolve,
    mock_prepare,
    monkeypatch,
):
    monkeypatch.delenv("NO_COLOR", raising=False)
    verified = _verified_context(project="付款[prod]", profile="公司[prod]")
    mock_resolve.return_value = verified.resolved
    mock_prepare.return_value = VerifiedRuntime(verified=verified, environment={})
    stdout = TerminalBuffer()
    stderr = TerminalBuffer()

    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        exit_code = main(["context", "prod", "--json"])

    assert exit_code == 0
    assert "\x1b[" not in stdout.getvalue()
    assert '"project": "付款[prod]"' in stdout.getvalue()
    assert '"profile": "公司[prod]"' in stdout.getvalue()
    assert "\x1b[" in stderr.getvalue()
