"""Tests for the awsui command-line entry point."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from awsui.cli.bind import BindCommandCancelled, BindCommandError, BindResult
from awsui.cli.initialization import InitCommandCancelled, InitCommandError
from awsui.cli.main import main
from awsui.context.dashboard import ContextItem, ContextStatus, DashboardSnapshot
from awsui.context.resolution import ContextResolutionError, ResolvedContext
from awsui.context.runtime import VerifiedRuntime
from awsui.context.verification import (
    AccountMismatchError,
    ContextVerificationError,
    VerifiedContext,
)
from awsui.doctor import DoctorCheck, DoctorReport
from awsui.profiles.catalog import ProfileCatalogError
from awsui.project.config import ProjectConfigNotFoundError
from awsui.project.initialization import InitResult, InitializedEnvironment
from awsui.settings import UserSettingsWriteError


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


def dashboard_snapshot() -> DashboardSnapshot:
    return DashboardSnapshot(
        project="payment-service",
        config_path=Path("/project/.awsui.yaml"),
        bindings_path=Path("/home/user/.config/awsui/bindings.json"),
        contexts=(
            ContextItem(
                name="dev",
                expected_account="111111111111",
                region="us-east-1",
                protected=False,
                profile="company-dev",
                status=ContextStatus.READY,
            ),
            ContextItem(
                name="qa",
                expected_account="222222222222",
                region="us-east-1",
                protected=False,
                profile="missing-qa",
                status=ContextStatus.PROFILE_MISSING,
            ),
            ContextItem(
                name="prod",
                expected_account="999999999999",
                region="ap-northeast-1",
                protected=True,
                profile=None,
                status=ContextStatus.UNBOUND,
            ),
        ),
    )


class TestMain:
    """Tests for CLI dispatch."""

    def test_default_options_show_cli_help(self, capsys):
        exit_code = main([])

        assert exit_code == 0
        output = capsys.readouterr().out
        assert "Usage: awsui" in output
        assert "context" in output
        assert "bind" in output

    def test_language_switch_is_remembered(
        self,
        capsys,
        isolated_cli_settings,
    ):
        exit_code = main(["--lang", "zh-TW"])

        assert exit_code == 0
        assert capsys.readouterr().out == "語言已切換為繁體中文。\n"

        assert main([]) == 0
        output = capsys.readouterr().out
        assert "用法： awsui" in output
        assert "快速開始" in output
        assert "初始化此專案" in output
        assert "--lang {zh-TW,en}" in output
        assert "--log-level" not in output
        assert json.loads(isolated_cli_settings.read_text(encoding="utf-8")) == {
            "language": "zh-TW",
            "version": 1,
        }

        assert main(["--lang", "en"]) == 0
        assert capsys.readouterr().out == "Language switched to English.\n"
        assert main([]) == 0
        assert "Usage: awsui" in capsys.readouterr().out

    def test_language_switch_with_help_is_persisted(
        self,
        capsys,
        isolated_cli_settings,
    ):
        with pytest.raises(SystemExit) as exc_info:
            main(["--lang", "zh-TW", "--help"])

        assert exc_info.value.code == 0
        assert "用法： awsui" in capsys.readouterr().out
        assert (
            json.loads(isolated_cli_settings.read_text(encoding="utf-8"))["language"]
            == "zh-TW"
        )

    def test_explicit_language_repairs_damaged_settings(
        self,
        capsys,
        isolated_cli_settings,
    ):
        isolated_cli_settings.parent.mkdir(parents=True)
        isolated_cli_settings.write_text("{invalid", encoding="utf-8")

        assert main([]) == 1
        assert "Unable to load user settings" in capsys.readouterr().err

        assert main(["--lang", "zh-TW"]) == 0
        assert capsys.readouterr().out == "語言已切換為繁體中文。\n"
        assert (
            json.loads(isolated_cli_settings.read_text(encoding="utf-8"))["language"]
            == "zh-TW"
        )

    @patch("awsui.cli.main.load_dashboard")
    @patch("awsui.cli.main.save_settings")
    def test_language_write_failure_does_not_dispatch(
        self,
        mock_save_settings,
        mock_load_dashboard,
        capsys,
        isolated_cli_settings,
    ):
        mock_save_settings.side_effect = UserSettingsWriteError(
            isolated_cli_settings,
            "write denied",
        )

        exit_code = main(["--lang", "zh-TW", "context", "ls"])

        assert exit_code == 1
        assert "無法儲存語言偏好" in capsys.readouterr().err
        mock_load_dashboard.assert_not_called()

    @patch("awsui.cli.main.bind_environment")
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

    @patch("awsui.cli.main.bind_environment")
    @patch("awsui.cli.main.load_dashboard")
    def test_bind_list_success(self, mock_load_dashboard, mock_bind, capsys):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["bind", "ls"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert "Project: payment-service" in captured.out
        assert "company-dev" in captured.out
        assert "PROFILE MISSING" in captured.out
        assert "UNBOUND" in captured.out
        assert "PROTECTED" in captured.out
        mock_load_dashboard.assert_called_once_with()
        mock_bind.assert_not_called()

    @patch("awsui.cli.main.bind_environment")
    @patch("awsui.cli.main.load_dashboard")
    def test_bind_list_json_matches_context_list_schema(
        self,
        mock_load_dashboard,
        mock_bind,
        capsys,
    ):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["bind", "list", "--json"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        payload = json.loads(captured.out)
        assert list(payload) == ["project", "contexts"]
        assert payload["project"] == "payment-service"
        assert [context["environment"] for context in payload["contexts"]] == [
            "dev",
            "qa",
            "prod",
        ]
        assert payload["contexts"][1]["status"] == "profile-missing"
        mock_load_dashboard.assert_called_once_with()
        mock_bind.assert_not_called()

    @patch("awsui.cli.main.load_dashboard")
    def test_bind_list_source_error_returns_one(self, mock_load_dashboard, capsys):
        mock_load_dashboard.side_effect = ProfileCatalogError("profiles unavailable")

        exit_code = main(["bind", "ls"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "awsui bind: error: profiles unavailable" in captured.err
        assert "awsui doctor" in captured.err

    @patch("awsui.cli.main.bind_environment")
    def test_bind_json_is_restricted_to_list_aliases(self, mock_bind, capsys):
        exit_code = main(["bind", "prod", "--json"])

        assert exit_code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "only valid with `awsui bind ls` or `awsui bind list`" in captured.err
        mock_bind.assert_not_called()

    @patch("awsui.cli.main.initialize_project")
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

    @patch("awsui.cli.main.initialize_project")
    def test_init_error_and_cancellation_exit_codes(self, mock_initialize, capsys):
        mock_initialize.side_effect = InitCommandError("already exists")
        assert main(["init"]) == 1
        assert "awsui init: error: already exists" in capsys.readouterr().err

        mock_initialize.side_effect = InitCommandCancelled("cancelled")
        assert main(["init"]) == 130
        assert "awsui init: cancelled" in capsys.readouterr().err

    @patch("awsui.cli.main.diagnose")
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

    @patch("awsui.cli.main.diagnose")
    def test_doctor_returns_zero_when_healthy(self, mock_diagnose):
        mock_diagnose.return_value = DoctorReport(
            checks=(DoctorCheck("AWS CLI v2", True, "available"),)
        )

        assert main(["doctor"]) == 0

    @patch("awsui.cli.main.bind_environment")
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

    @patch("awsui.cli.main.bind_environment")
    def test_bind_error_returns_one(self, mock_bind, capsys):
        mock_bind.side_effect = BindCommandError("unknown environment 'prod'")

        exit_code = main(["bind", "prod"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "awsui bind: error: unknown environment" in captured.err

    @patch("awsui.cli.main.bind_environment")
    def test_bind_rejects_removed_profile_option(self, mock_bind):
        with pytest.raises(SystemExit) as exc_info:
            main(["--profile", "company-prod", "bind", "prod"])

        assert exc_info.value.code == 2
        mock_bind.assert_not_called()

    @patch("awsui.cli.main.bind_environment")
    def test_bind_cancelled_returns_130(self, mock_bind, capsys):
        mock_bind.side_effect = BindCommandCancelled()

        exit_code = main(["bind", "prod"])

        assert exit_code == 130
        assert "awsui bind: binding cancelled" in capsys.readouterr().err

    @patch("awsui.cli.main.bind_environment")
    def test_bind_keyboard_interrupt_returns_130(self, mock_bind, capsys):
        mock_bind.side_effect = KeyboardInterrupt

        exit_code = main(["bind", "prod"])

        assert exit_code == 130
        assert "awsui bind: binding cancelled" in capsys.readouterr().err

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
    def test_context_success(
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.load_dashboard")
    def test_context_list_success(
        self,
        mock_load_dashboard,
        mock_prepare,
        capsys,
    ):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["context", "ls"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert "Project: payment-service" in captured.out
        assert "Environment" in captured.out
        assert "dev" in captured.out
        assert "PROFILE MISSING" in captured.out
        assert "PROTECTED" in captured.out
        assert "UNBOUND" in captured.out
        mock_load_dashboard.assert_called_once_with()
        mock_prepare.assert_not_called()

    @patch("awsui.cli.main.load_dashboard")
    def test_context_list_json_success(self, mock_load_dashboard, capsys):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["context", "list", "--json"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        payload = json.loads(captured.out)
        assert list(payload) == ["project", "contexts"]
        assert payload == {
            "project": "payment-service",
            "contexts": [
                {
                    "environment": "dev",
                    "account": "111111111111",
                    "region": "us-east-1",
                    "profile": "company-dev",
                    "status": "ready",
                    "protected": False,
                },
                {
                    "environment": "qa",
                    "account": "222222222222",
                    "region": "us-east-1",
                    "profile": "missing-qa",
                    "status": "profile-missing",
                    "protected": False,
                },
                {
                    "environment": "prod",
                    "account": "999999999999",
                    "region": "ap-northeast-1",
                    "profile": None,
                    "status": "unbound",
                    "protected": True,
                },
            ],
        }

    @patch("awsui.cli.main.load_dashboard")
    def test_context_list_uses_traditional_chinese(self, mock_load_dashboard, capsys):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["--lang", "zh-TW", "context", "ls"])

        assert exit_code == 0
        output = capsys.readouterr().out
        assert "專案: payment-service" in output
        assert "環境" in output
        assert "找不到 PROFILE" in output
        assert "受保護環境" in output

    @patch("awsui.cli.main.load_dashboard")
    def test_context_list_json_is_language_neutral(self, mock_load_dashboard, capsys):
        mock_load_dashboard.return_value = dashboard_snapshot()

        exit_code = main(["--lang", "zh-TW", "context", "list", "--json"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert list(payload) == ["project", "contexts"]
        assert payload["contexts"][0]["status"] == "ready"

    @pytest.mark.parametrize(
        ("error", "next_step"),
        [
            (
                ProjectConfigNotFoundError(Path("/project"), "file not found"),
                "awsui init",
            ),
            (ProfileCatalogError("profiles unavailable"), "awsui doctor"),
        ],
    )
    @patch("awsui.cli.main.load_dashboard")
    def test_context_list_source_errors_return_one(
        self,
        mock_load_dashboard,
        error,
        next_step,
        capsys,
    ):
        mock_load_dashboard.side_effect = error

        exit_code = main(["context", "ls"])

        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "awsui context: error:" in captured.err
        assert next_step in captured.err

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.run_command", return_value=7)
    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.run_command")
    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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

    @patch("awsui.cli.main.run_command", return_value=0)
    @patch("awsui.cli.main.select_interactive_shell", return_value="/bin/zsh")
    @patch("awsui.cli.main.prepare_resolved_runtime")
    @patch("awsui.cli.main.resolve_context")
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
