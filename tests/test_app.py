"""Tests for the project-aware Textual Context Dashboard."""

import asyncio
from contextlib import nullcontext
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from awsui.app import AWSUIApp, ContextList, InformationScreen, LaunchScreen
from awsui.context_engine import ResolvedContext
from awsui.context_runtime import VerifiedRuntime
from awsui.context_verification import AccountMismatchError, VerifiedContext
from awsui.doctor_command import DoctorCheck, DoctorReport
from awsui.init_screen import InitializationScreen, InitWizardStep
from awsui.profile_catalog import ProfileCatalog
from awsui.tui_context import (
    ContextItem,
    ContextStatus,
    DashboardSnapshot,
    DetectedTool,
)


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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.snapshot is None
            assert app.sub_title == "No project"
            assert app.query_one("#initialize").display is True
            assert app.query_one("#verify").display is False

    run(scenario())


@pytest.mark.parametrize(
    ("size", "lang"),
    [((80, 24), "en"), ((120, 36), "zh-TW")],
)
def test_initialize_opens_native_textual_wizard(tmp_path, size, lang):
    async def scenario():
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(lang=lang, start_dir=tmp_path, base_environment={})
        app.suspend = Mock(return_value=nullcontext())
        with patch(
            "awsui.init_screen.load_profile_catalog",
            return_value=ProfileCatalog.from_profiles(()),
        ):
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                app.action_initialize()
                await pilot.pause()
                assert isinstance(app.screen, InitializationScreen)
                assert app.screen.query_one("#init-project-name").value == tmp_path.name
                app.suspend.assert_not_called()

    run(scenario())


def test_native_init_creates_verified_dev_and_qa_contexts(tmp_path):
    async def scenario():
        local_profile = {
            "name": "company-developer",
            "kind": "sso",
            "account": None,
            "role": None,
            "region": "ap-northeast-1",
            "session": "company",
            "source": str(tmp_path / "config"),
        }
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        screen = InitializationScreen(
            start_dir=tmp_path,
            bindings_path=tmp_path / "bindings.json",
            base_environment={"AWS_ACCESS_KEY_ID": "must-not-leak"},
            translations=app.lang,
            identity_provider=lambda _profile: {
                "Account": "111111111111",
                "Arn": "arn:aws:sts::111111111111:assumed-role/Developer/test",
            },
            profiles_loader=lambda: [local_profile],
            cli_info_provider=lambda: None,
        )
        async with app.run_test(size=(100, 34)) as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen.query_one("#init-project-name").value = "payment-service"
            screen._continue_project()

            for environment in ("dev", "qa"):
                screen.query_one("#init-environment-name").value = environment
                screen._start_verification()
                worker = screen.verification_worker
                assert worker is not None
                await worker.wait()
                await pilot.pause()
                assert screen.step is InitWizardStep.REVIEW
                if environment == "dev":
                    screen._add_environment()

            assert [item.name for item in screen.environments] == ["dev", "qa"]
            screen._finish()
            await pilot.pause()

        config = (tmp_path / ".awsui.yaml").read_text(encoding="utf-8")
        bindings = (tmp_path / "bindings.json").read_text(encoding="utf-8")
        assert "dev:" in config
        assert "qa:" in config
        assert "company-developer" not in config
        assert "company-developer" in bindings

    run(scenario())


def test_native_init_returns_after_official_profile_creation(tmp_path):
    async def scenario():
        created_profile = {
            "name": "payment-service-dev",
            "kind": "sso",
            "account": None,
            "role": None,
            "region": "ap-northeast-1",
            "session": "company",
            "source": str(tmp_path / "config"),
        }
        state = {"created": False}
        commands = []

        def profiles_loader():
            return [created_profile] if state["created"] else []

        def command_runner(command, **_kwargs):
            commands.append(command)
            state["created"] = True
            return 0

        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        app.suspend = Mock(return_value=nullcontext())
        screen = InitializationScreen(
            start_dir=tmp_path,
            bindings_path=tmp_path / "bindings.json",
            base_environment={},
            translations=app.lang,
            profiles_loader=profiles_loader,
            command_runner=command_runner,
            cli_info_provider=lambda: None,
        )
        async with app.run_test(size=(100, 34)) as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen.query_one("#init-project-name").value = "payment-service"
            screen._continue_project()
            screen.query_one("#init-environment-name").value = "dev"
            screen._open_profile_creation()
            method_list = screen.query_one("#init-method-list")
            assert method_list.get_option_at_index(0).id == "sso"
            with patch("awsui.init_screen.sys.stdout", new=StringIO()):
                screen._start_profile_creation()
            await pilot.pause()

            assert screen.step is InitWizardStep.CONTEXT
            assert screen.selected_profile == "payment-service-dev"
            assert screen.query_one("#init-region").value == "ap-northeast-1"
            assert commands == [
                [
                    "aws",
                    "configure",
                    "sso",
                    "--profile",
                    "payment-service-dev",
                ]
            ]
            app.suspend.assert_called_once()

    run(scenario())


def test_native_init_cancel_discards_verified_draft(tmp_path):
    async def scenario():
        local_profile = {
            "name": "company-dev",
            "kind": "sso",
            "account": None,
            "role": None,
            "region": "ap-northeast-1",
            "session": "company",
            "source": str(tmp_path / "config"),
        }
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        screen = InitializationScreen(
            start_dir=tmp_path,
            bindings_path=tmp_path / "bindings.json",
            base_environment={},
            translations=app.lang,
            identity_provider=lambda _profile: {"Account": "111111111111"},
            profiles_loader=lambda: [local_profile],
            cli_info_provider=lambda: None,
        )
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen._continue_project()
            screen.query_one("#init-environment-name").value = "dev"
            screen._start_verification()
            worker = screen.verification_worker
            assert worker is not None
            await worker.wait()
            await pilot.pause()

            screen.action_cancel()
            assert app.screen is screen
            assert screen.discard_armed is True
            screen.action_cancel()
            await pilot.pause()

        assert not (tmp_path / ".awsui.yaml").exists()
        assert not (tmp_path / "bindings.json").exists()

    run(scenario())


def test_dashboard_renders_contexts_and_keyboard_navigation(tmp_path):
    async def scenario():
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)):
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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with (
            patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch("awsui.app.diagnose", return_value=report),
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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={"PATH": "/bin"})
        app.suspend = Mock(return_value=nullcontext())
        with (
            patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch(
                "awsui.app.prepare_context_runtime", return_value=verified_runtime
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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        app.suspend = Mock(return_value=nullcontext())
        with (
            patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)),
            patch("awsui.app.prepare_context_runtime", side_effect=mismatch),
            patch("awsui.app.run_command") as mock_run,
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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(start_dir=tmp_path, base_environment={})
        with patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)):
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
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(lang=lang, start_dir=tmp_path, base_environment={})
        with patch("awsui.app.load_dashboard", return_value=snapshot(tmp_path)):
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                assert app.query_one("#action-bar").display is True
                app.action_show_help()
                await pilot.pause()
                assert isinstance(app.screen, InformationScreen)
                assert app.screen.modal_title == expected_help_title

    run(scenario())
