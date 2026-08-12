"""Tests for the project-aware Textual Context Dashboard."""

import asyncio
from contextlib import nullcontext
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from awsui.context.dashboard import (
    ContextItem,
    ContextStatus,
    DashboardSnapshot,
)
from awsui.context.resolution import ResolvedContext
from awsui.context.runtime import VerifiedRuntime
from awsui.context.verification import AccountMismatchError, VerifiedContext
from awsui.doctor import DoctorCheck, DoctorReport
from awsui.tui.app import AWSUIApp
from awsui.tui.launch import DetectedTool
from awsui.tui.screens import InformationScreen, LaunchScreen
from awsui.tui.widgets import ContextList


def snapshot(tmp_path: Path) -> DashboardSnapshot:
    return DashboardSnapshot(
        project="payment-service",
        config_path=tmp_path / ".awsui.yaml",
        bindings_path=tmp_path / "bindings.json",
        contexts=(
            ContextItem(
                "dev",
                "111111111111",
                "ap-northeast-1",
                False,
                "company-dev",
                ContextStatus.READY,
            ),
            ContextItem(
                "prod",
                "999999999999",
                "ap-northeast-1",
                True,
                None,
                ContextStatus.UNBOUND,
            ),
        ),
    )


def runtime(tmp_path: Path) -> VerifiedRuntime:
    resolved = ResolvedContext(
        project="payment-service",
        environment="dev",
        expected_account="111111111111",
        region="ap-northeast-1",
        profile="company-dev",
        protected=False,
        project_config_path=tmp_path / ".awsui.yaml",
        bindings_path=tmp_path / "bindings.json",
    )
    return VerifiedRuntime(
        verified=VerifiedContext(
            resolved,
            "111111111111",
            "arn:aws:sts::111111111111:assumed-role/Developer/session",
        ),
        environment={
            "AWS_PROFILE": "company-dev",
            "AWS_REGION": "ap-northeast-1",
            "AWS_DEFAULT_REGION": "ap-northeast-1",
            "SHELL": "/bin/zsh",
        },
    )


def run(coroutine):
    return asyncio.run(coroutine)


def test_no_project_renders_onboarding(tmp_path):
    async def scenario():
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.snapshot is None
            assert app.sub_title == "No project"
            assert app.query_one("#initialize").display is True
            assert app.query_one("#verify").display is False

    run(scenario())


def test_dashboard_renders_contexts_and_keyboard_navigation(tmp_path):
    async def scenario():
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)):
            async with app.run_test() as pilot:
                await pilot.pause()
                assert app.sub_title == "payment-service"
                assert app.theme == "awsui-graphite"
                assert len(app.query_one("#context-list", ContextList).children) == 2
                assert app.selected_environment == "dev"
                await pilot.press("down")
                assert app.selected_environment == "prod"
                assert app.query_one("#verify").display is False
                app._refresh_context_list()
                await pilot.pause()
                assert app.query_one("#context-list", ContextList).index == 1
                assert app.selected_environment == "prod"

    run(scenario())


def test_doctor_modal_mounts_with_textual_safe_rich_styles(tmp_path):
    async def scenario():
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
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with (
            patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch("awsui.tui.app.diagnose", return_value=report),
        ):
            async with app.run_test() as pilot:
                await pilot.click("#doctor")
                await pilot.pause()
                assert isinstance(app.screen, InformationScreen)
                assert app.screen.modal_title == "Doctor"
                console = Console(file=StringIO(), record=True, width=100)
                console.print(app.screen.renderable)
                assert "Next steps" in console.export_text()

    run(scenario())


def test_verify_success_updates_session_identity(tmp_path):
    async def scenario():
        verified_runtime = runtime(tmp_path)
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={"PATH": "/bin"})
        app.suspend = Mock(return_value=nullcontext())
        with (
            patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch(
                "awsui.tui.app.prepare_context_runtime", return_value=verified_runtime
            ) as mock_prepare,
        ):
            async with app.run_test() as pilot:
                await pilot.pause()
                await pilot.press("v")
                await pilot.pause()
                assert app.statuses["dev"] is ContextStatus.VERIFIED
                assert app.verified["dev"].actual_account == "111111111111"
                mock_prepare.assert_called_once()

    run(scenario())


def test_mismatch_blocks_child_launch(tmp_path):
    async def scenario():
        mismatch = AccountMismatchError(
            project="payment-service",
            environment="dev",
            profile="company-dev",
            expected_account="111111111111",
            actual_account="999999999999",
        )
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        app.suspend = Mock(return_value=nullcontext())
        with (
            patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch("awsui.tui.app.prepare_context_runtime", side_effect=mismatch),
            patch("awsui.tui.app.run_command") as mock_run,
        ):
            async with app.run_test() as pilot:
                await pilot.pause()
                app._launch_result("codex")
                await pilot.pause()
                assert app.statuses["dev"] is ContextStatus.MISMATCH
                assert app.actual_accounts["dev"] == "999999999999"
                mock_run.assert_not_called()

    run(scenario())


def test_launch_screen_prefills_first_detected_tool():
    screen = LaunchScreen(
        "dev",
        (DetectedTool("Codex", "codex", "/tools/codex"),),
        protected=False,
    )

    assert screen.tools[0].executable == "codex"


def test_launch_screen_mounts_with_only_custom_command(tmp_path):
    async def scenario():
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)):
            async with app.run_test() as pilot:
                app.push_screen(LaunchScreen("dev", (), protected=False))
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, LaunchScreen)
                assert screen.query_one("#launch-command").value == ""
                assert screen.query_one("#launch-confirm").label.plain == (
                    "Verify & Launch"
                )

    run(scenario())


@pytest.mark.parametrize(
    ("size", "lang", "expected_help_title"),
    [
        ((80, 24), "en", "Keyboard shortcuts"),
        ((120, 36), "zh-TW", "鍵盤快捷鍵"),
    ],
)
def test_dashboard_and_help_mount_at_supported_viewports(
    tmp_path,
    size,
    lang,
    expected_help_title,
):
    async def scenario():
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(lang=lang, start_dir=tmp_path, base_environment={})
        with patch("awsui.tui.app.load_dashboard", return_value=snapshot(tmp_path)):
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                assert app.query_one("#action-bar").display is True
                app.action_show_help()
                await pilot.pause()
                assert isinstance(app.screen, InformationScreen)
                assert app.screen.modal_title == expected_help_title

    run(scenario())
