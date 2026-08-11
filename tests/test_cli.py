"""Tests for the awsui command-line entry point."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from awsui import app
from awsui.bind_command import BindCommandCancelled, BindCommandError, BindResult
from awsui.cli import build_parser, main, parse_args
from awsui.context_engine import ContextResolutionError, ResolvedContext
from awsui.context_runtime import VerifiedRuntime
from awsui.context_verification import (
    AccountMismatchError,
    ContextVerificationError,
    VerifiedContext,
)
from awsui.doctor_command import DoctorCheck, DoctorReport
from awsui.init_command import (
    InitCommandCancelled,
    InitCommandError,
    InitResult,
    InitializedEnvironment,
)


def resolved_context(
    *,
    protected: bool = True,
    project: str = "payment-service",
    profile: str = "company-prod",
) -> ResolvedContext:
    return ResolvedContext(
        project=project,
        environment="prod",
        expected_account="999999999999",
        region="ap-northeast-1",
        profile=profile,
        protected=protected,
        project_config_path=Path("/project/.awsui.yaml"),
        bindings_path=Path("/home/user/.config/awsui/bindings.json"),
    )


def verified_context(
    *,
    protected: bool = True,
    project: str = "payment-service",
    profile: str = "company-prod",
) -> VerifiedContext:
    return VerifiedContext(
        resolved=resolved_context(
            protected=protected,
            project=project,
            profile=profile,
        ),
        actual_account="999999999999",
    )


def verified_runtime(
    *,
    protected: bool = True,
    project: str = "payment-service",
    profile: str = "company-prod",
) -> VerifiedRuntime:
    return VerifiedRuntime(
        verified=verified_context(
            protected=protected,
            project=project,
            profile=profile,
        ),
        environment={
            "AWS_PROFILE": profile,
            "AWS_REGION": "ap-northeast-1",
            "AWS_DEFAULT_REGION": "ap-northeast-1",
            "SHELL": "/bin/zsh",
        },
    )


class TestParseArgs:
    """Tests for command-line argument parsing."""

    def test_default_arguments(self):
        args = parse_args([])

        assert not hasattr(args, "profile")
        assert not hasattr(args, "region")
        assert args.lang == "en"
        assert args.log_level == "INFO"
        assert args.command is None

    @pytest.mark.parametrize("option", ["--profile", "--region"])
    def test_removed_legacy_tui_options_are_rejected(self, option):
        with pytest.raises(SystemExit) as exc_info:
            parse_args([option, "legacy-value"])

        assert exc_info.value.code == 2

    def test_language_argument_english(self):
        args = parse_args(["--lang", "en"])

        assert args.lang == "en"

    def test_language_argument_chinese(self):
        args = parse_args(["--lang", "zh-TW"])

        assert args.lang == "zh-TW"

    def test_log_level_debug(self):
        args = parse_args(["--log-level", "DEBUG"])

        assert args.log_level == "DEBUG"

    def test_log_level_warning(self):
        args = parse_args(["--log-level", "WARNING"])

        assert args.log_level == "WARNING"

    def test_multiple_arguments(self):
        args = parse_args(
            [
                "--lang",
                "zh-TW",
                "--log-level",
                "ERROR",
            ]
        )

        assert args.lang == "zh-TW"
        assert args.log_level == "ERROR"

    def test_help_identifies_existing_options(self):
        help_text = build_parser().format_help()

        assert "--profile" not in help_text
        assert "--region" not in help_text
        assert "--lang" in help_text
        assert "--log-level" in help_text
        assert "bind" in help_text
        assert "init" in help_text
        assert "context" in help_text
        assert "run" in help_text
        assert "shell" in help_text
        assert "doctor" in help_text

    def test_init_subcommand(self):
        args = parse_args(["init"])

        assert args.command == "init"

    def test_doctor_subcommand(self):
        args = parse_args(["doctor"])

        assert args.command == "doctor"

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--version"])

        assert exc_info.value.code == 0
        assert capsys.readouterr().out == "awsui 0.2.0\n"

    def test_bind_subcommand(self):
        args = parse_args(["bind", "prod"])

        assert args.command == "bind"
        assert args.environment == "prod"

    def test_bind_requires_environment(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["bind"])

        assert exc_info.value.code == 2

    def test_context_subcommand(self):
        args = parse_args(["context", "prod"])

        assert args.command == "context"
        assert args.environment == "prod"
        assert args.json is False

    def test_context_json_subcommand(self):
        args = parse_args(["context", "prod", "--json"])

        assert args.command == "context"
        assert args.environment == "prod"
        assert args.json is True

    def test_context_requires_environment(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["context"])

        assert exc_info.value.code == 2

    def test_run_subcommand_with_separator(self):
        args = parse_args(["run", "prod", "--", "terraform", "plan", "-out=x"])

        assert args.command == "run"
        assert args.environment == "prod"
        assert args.child_command == ["terraform", "plan", "-out=x"]

    def test_run_subcommand_without_separator(self):
        args = parse_args(["run", "prod", "aws", "s3", "ls"])

        assert args.child_command == ["aws", "s3", "ls"]

    def test_environment_command_shorthand(self):
        args = parse_args(["prod", "--", "codex", "--quiet"])

        assert args.command == "run"
        assert args.environment == "prod"
        assert args.child_command == ["codex", "--quiet"]

    def test_environment_only_shorthand_opens_shell(self):
        args = parse_args(["qa"])

        assert args.command == "shell"
        assert args.environment == "qa"

    @pytest.mark.parametrize(
        "argv",
        [
            ["prod", "codex"],
            ["prod", "--"],
        ],
    )
    def test_shorthand_rejects_ambiguous_or_empty_commands(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(argv)

        assert exc_info.value.code == 2

    def test_reserved_subcommand_names_keep_existing_meaning(self):
        args = parse_args(["run", "prod", "--", "codex"])

        assert args.command == "run"
        assert args.environment == "prod"

    def test_help_documents_primary_and_compatible_syntax(self):
        help_text = build_parser().format_help()

        assert "awsui prod -- codex" in help_text
        assert "awsui prod" in help_text
        assert "awsui run prod -- codex" in help_text

    def test_shell_subcommand(self):
        args = parse_args(["shell", "prod"])

        assert args.command == "shell"
        assert args.environment == "prod"


class TestMain:
    """Tests for CLI-to-TUI dispatch."""

    @patch("awsui.cli.run_tui")
    def test_default_options_launch_tui(self, mock_run_tui):
        exit_code = main([])

        assert exit_code == 0
        mock_run_tui.assert_called_once_with(
            lang="en",
            log_level="INFO",
        )

    @patch("awsui.cli.run_tui")
    def test_explicit_options_launch_tui(self, mock_run_tui):
        exit_code = main(
            [
                "--lang",
                "zh-TW",
                "--log-level",
                "DEBUG",
            ]
        )

        assert exit_code == 0
        mock_run_tui.assert_called_once_with(
            lang="zh-TW",
            log_level="DEBUG",
        )

    @patch("awsui.cli.main", return_value=7)
    def test_app_module_entry_point_delegates_to_cli(self, mock_cli_main):
        exit_code = app.main()

        assert exit_code == 7
        mock_cli_main.assert_called_once_with()

    @patch("awsui.cli.bind_environment")
    def test_bind_success(self, mock_bind, capsys):
        mock_bind.return_value = BindResult(
            project="payment-service",
            environment="prod",
            profile="company-prod",
            previous_profile=None,
            changed=True,
        )

        exit_code = main(["bind", "prod"])

        assert exit_code == 0
        assert capsys.readouterr().out == "Bound payment-service/prod → company-prod\n"
        mock_bind.assert_called_once_with("prod")

    @patch("awsui.cli.initialize_project")
    def test_init_success(self, mock_initialize, capsys):
        mock_initialize.return_value = InitResult(
            project="payment-service",
            config_path=Path("/project/.awsui.yaml"),
            environments=(
                InitializedEnvironment(
                    name="dev",
                    profile="company-dev",
                    account="111111111111",
                    region="us-east-1",
                    protected=False,
                ),
                InitializedEnvironment(
                    name="prod",
                    profile="company-prod",
                    account="999999999999",
                    region="ap-northeast-1",
                    protected=True,
                ),
            ),
        )

        exit_code = main(["init"])

        assert exit_code == 0
        output = capsys.readouterr().out
        assert f"Created {Path('/project/.awsui.yaml')}" in output
        assert "dev: 111111111111 · us-east-1" in output
        assert "prod: 999999999999 · ap-northeast-1 · PROTECTED" in output

    @patch("awsui.cli.initialize_project")
    def test_init_error_and_cancellation_exit_codes(self, mock_initialize, capsys):
        mock_initialize.side_effect = InitCommandError("already exists")
        assert main(["init"]) == 1
        assert "awsui init: error: already exists" in capsys.readouterr().err

        mock_initialize.side_effect = InitCommandCancelled("cancelled")
        assert main(["init"]) == 130
        assert "awsui init: cancelled" in capsys.readouterr().err

    @patch("awsui.cli.diagnose")
    def test_doctor_renders_checks_and_fails_when_unhealthy(
        self,
        mock_diagnose,
        capsys,
    ):
        mock_diagnose.return_value = DoctorReport(
            checks=(
                DoctorCheck("AWS CLI v2", True, "available"),
                DoctorCheck("Context prod", False, "not bound"),
            )
        )

        exit_code = main(["doctor"])

        assert exit_code == 1
        assert capsys.readouterr().out == (
            "✓ AWS CLI v2: available\n✗ Context prod: not bound\n"
        )

    @patch("awsui.cli.diagnose")
    def test_doctor_returns_zero_when_healthy(self, mock_diagnose):
        mock_diagnose.return_value = DoctorReport(
            checks=(DoctorCheck("AWS CLI v2", True, "available"),)
        )

        assert main(["doctor"]) == 0

    @patch("awsui.cli.bind_environment")
    def test_bind_unchanged(self, mock_bind, capsys):
        mock_bind.return_value = BindResult(
            project="payment-service",
            environment="prod",
            profile="company-prod",
            previous_profile="company-prod",
            changed=False,
        )

        exit_code = main(["bind", "prod"])

        assert exit_code == 0
        assert "Binding unchanged:" in capsys.readouterr().out

    @patch("awsui.cli.bind_environment")
    def test_bind_error_returns_one(self, mock_bind, capsys):
        mock_bind.side_effect = BindCommandError("unknown environment 'prod'")

        exit_code = main(["bind", "prod"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "awsui bind: error: unknown environment" in captured.err

    @patch("awsui.cli.bind_environment")
    def test_bind_rejects_removed_profile_option(self, mock_bind):
        with pytest.raises(SystemExit) as exc_info:
            main(["--profile", "company-prod", "bind", "prod"])

        assert exc_info.value.code == 2
        mock_bind.assert_not_called()

    @patch("awsui.cli.bind_environment")
    def test_bind_cancelled_returns_130(self, mock_bind, capsys):
        mock_bind.side_effect = BindCommandCancelled()

        exit_code = main(["bind", "prod"])

        assert exit_code == 130
        assert "awsui bind: binding cancelled" in capsys.readouterr().err

    @patch("awsui.cli.bind_environment")
    def test_bind_keyboard_interrupt_returns_130(self, mock_bind, capsys):
        mock_bind.side_effect = KeyboardInterrupt

        exit_code = main(["bind", "prod"])

        assert exit_code == 130
        assert "awsui bind: binding cancelled" in capsys.readouterr().err

    @patch("awsui.cli.run_tui")
    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_success(
        self,
        mock_resolve,
        mock_prepare,
        mock_run_tui,
        capsys,
    ):
        resolved = resolved_context()
        mock_resolve.return_value = resolved
        mock_prepare.return_value = VerifiedRuntime(
            verified=VerifiedContext(
                resolved=resolved,
                actual_account="999999999999",
            ),
            environment={},
        )

        exit_code = main(["context", "prod"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.out == (
            "payment-service · PROD · PROTECTED\n"
            "Expected account: 999999999999\n"
            "Authenticated account: 999999999999\n"
            "Region: ap-northeast-1\n"
            "Local profile: company-prod\n"
            "Status: ✓ VERIFIED\n"
        )
        assert captured.err == "Authenticating and verifying AWS identity...\n"
        mock_resolve.assert_called_once_with("prod")
        assert mock_prepare.call_args.args == (resolved,)
        assert mock_prepare.call_args.kwargs["login_output"] is not None
        mock_run_tui.assert_not_called()

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_non_protected_heading(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        mock_resolve.return_value = resolved_context(protected=False)
        mock_prepare.return_value = verified_runtime(protected=False)

        exit_code = main(["context", "prod"])

        assert exit_code == 0
        assert capsys.readouterr().out.startswith("payment-service · PROD\n")

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_json_success(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        resolved = resolved_context()
        mock_resolve.return_value = resolved
        mock_prepare.return_value = VerifiedRuntime(
            verified=VerifiedContext(
                resolved=resolved,
                actual_account="999999999999",
            ),
            environment={},
        )

        exit_code = main(["context", "prod", "--json"])

        assert exit_code == 0
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert list(payload) == [
            "project",
            "environment",
            "expected_account",
            "actual_account",
            "region",
            "profile",
            "verified",
        ]
        assert payload == {
            "project": "payment-service",
            "environment": "prod",
            "expected_account": "999999999999",
            "actual_account": "999999999999",
            "region": "ap-northeast-1",
            "profile": "company-prod",
            "verified": True,
        }
        assert captured.out.endswith("\n")
        assert captured.err == "Authenticating and verifying AWS identity...\n"

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_json_preserves_unicode(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        resolved = resolved_context(project="付款服務", profile="公司-prod")
        mock_resolve.return_value = resolved
        mock_prepare.return_value = VerifiedRuntime(
            verified=VerifiedContext(
                resolved=resolved,
                actual_account="999999999999",
            ),
            environment={},
        )

        exit_code = main(["context", "prod", "--json"])

        assert exit_code == 0
        output = capsys.readouterr().out
        assert '"project": "付款服務"' in output
        assert '"profile": "公司-prod"' in output
        assert "\\u" not in output

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_json_resolution_error_returns_one(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        mock_resolve.side_effect = ContextResolutionError("binding unavailable")

        exit_code = main(["context", "prod", "--json"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "awsui context: error: binding unavailable\n"
        mock_prepare.assert_not_called()

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_verification_error_returns_one(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        mock_resolve.return_value = resolved_context()
        mock_prepare.side_effect = ContextVerificationError("identity unavailable")

        exit_code = main(["context", "prod"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "Authenticating and verifying AWS identity...\n"
            "awsui context: error: identity unavailable\n"
        )

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_json_account_mismatch_returns_one(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        mock_resolve.return_value = resolved_context()
        mock_prepare.side_effect = AccountMismatchError(
            project="payment-service",
            environment="prod",
            profile="company-prod",
            expected_account="999999999999",
            actual_account="111111111111",
        )

        exit_code = main(["context", "prod", "--json"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "Authenticating and verifying AWS identity...\n"
            "AWS CONTEXT MISMATCH\n"
            "\n"
            "Project: payment-service\n"
            "Environment: PROD\n"
            "Expected account: 999999999999\n"
            "Authenticated account: 111111111111\n"
        )

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_json_keyboard_interrupt_returns_130(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        mock_resolve.return_value = resolved_context()
        mock_prepare.side_effect = KeyboardInterrupt

        exit_code = main(["context", "prod", "--json"])

        assert exit_code == 130
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "Authenticating and verifying AWS identity...\n"
            "awsui context: verification cancelled\n"
        )

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_context_rejects_removed_region_option(
        self,
        mock_resolve,
        mock_prepare,
    ):
        with pytest.raises(SystemExit) as exc_info:
            main(["--region", "us-west-2", "context", "prod"])

        assert exc_info.value.code == 2
        mock_resolve.assert_not_called()
        mock_prepare.assert_not_called()

    @patch("awsui.cli.run_command", return_value=7)
    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_run_launches_exact_argv_and_returns_child_code(
        self,
        mock_resolve,
        mock_prepare,
        mock_run_command,
        capsys,
    ):
        resolved = resolved_context()
        runtime = verified_runtime()
        mock_resolve.return_value = resolved
        mock_prepare.return_value = runtime

        exit_code = main(["run", "prod", "--", "terraform", "plan", "-out=x"])

        assert exit_code == 7
        mock_run_command.assert_called_once_with(
            ["terraform", "plan", "-out=x"],
            environment=runtime.environment,
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "payment-service · PROD · PROTECTED" in captured.err
        assert "Launching: terraform plan -out=x" in captured.err

    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_run_requires_command_before_aws_io(
        self,
        mock_resolve,
        mock_prepare,
        capsys,
    ):
        exit_code = main(["run", "prod"])

        assert exit_code == 2
        assert "a command is required" in capsys.readouterr().err
        mock_resolve.assert_not_called()
        mock_prepare.assert_not_called()

    @patch("awsui.cli.run_command")
    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_run_mismatch_never_launches_child(
        self,
        mock_resolve,
        mock_prepare,
        mock_run_command,
        capsys,
    ):
        mock_resolve.return_value = resolved_context()
        mock_prepare.side_effect = AccountMismatchError(
            project="payment-service",
            environment="prod",
            profile="company-prod",
            expected_account="999999999999",
            actual_account="111111111111",
        )

        exit_code = main(["run", "prod", "--", "claude"])

        assert exit_code == 1
        assert "Command was not started." in capsys.readouterr().err
        mock_run_command.assert_not_called()

    @patch("awsui.cli.run_command", return_value=0)
    @patch("awsui.cli.select_interactive_shell", return_value="/bin/zsh")
    @patch("awsui.cli.prepare_resolved_runtime")
    @patch("awsui.cli.resolve_context")
    def test_shell_launches_selected_shell(
        self,
        mock_resolve,
        mock_prepare,
        mock_select_shell,
        mock_run_command,
        capsys,
    ):
        runtime = verified_runtime()
        mock_resolve.return_value = resolved_context()
        mock_prepare.return_value = runtime

        exit_code = main(["shell", "prod"])

        assert exit_code == 0
        mock_select_shell.assert_called_once_with(runtime.environment)
        mock_run_command.assert_called_once_with(
            ["/bin/zsh"],
            environment=runtime.environment,
        )
        assert "Launching shell: /bin/zsh" in capsys.readouterr().err
