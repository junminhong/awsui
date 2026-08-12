"""Tests for the native Textual project-initialization workflow."""

import asyncio
from contextlib import nullcontext
from io import StringIO
from unittest.mock import Mock, patch

import pytest

from awsui.profiles.catalog import ProfileCatalog
from awsui.tui.app import AWSUIApp
from awsui.tui.initialization import InitializationScreen, InitWizardStep


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.mark.parametrize(
    ("size", "lang"),
    [((80, 24), "en"), ((120, 36), "zh-TW")],
)
def test_initialize_opens_native_textual_wizard(tmp_path, size, lang):
    async def scenario():
        with patch("awsui.tui.app.get_logger"):
            app = AWSUIApp(lang=lang, start_dir=tmp_path, base_environment={})
        app.suspend = Mock(return_value=nullcontext())
        with patch(
            "awsui.tui.initialization.load_profile_catalog",
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
        with patch("awsui.tui.app.get_logger"):
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

        with patch("awsui.tui.app.get_logger"):
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
            with patch("awsui.tui.initialization.sys.stdout", new=StringIO()):
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
        with patch("awsui.tui.app.get_logger"):
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
