"""Tests for interactive project initialization."""

from io import StringIO
from unittest.mock import patch

import pytest

from awsui.aws_cli import AwsCliInfo
from awsui.cli.initialization import (
    InitCommandCancelled,
    InitCommandError,
    initialize_project,
)
from awsui.project.bindings import LocalBindingsWriteError, load_bindings
from awsui.project.config import load_project_config


def profile(name: str, region: str):
    return {
        "name": name,
        "kind": "sso",
        "account": None,
        "role": None,
        "region": region,
        "session": "company",
        "source": "/home/user/.aws/config",
    }


class TestInitializeProject:
    def test_creates_verified_multi_environment_project(self, tmp_path):
        bindings_path = tmp_path / "bindings.json"
        stdin = StringIO("payment-service\ndev\n1\n\nn\nprod\n2\n\ny\n\n")
        identities = {
            "alpha-dev": {"Account": "111111111111"},
            "zeta-prod": {"Account": "999999999999"},
        }

        profiles = [
            profile("zeta-prod", "ap-northeast-1"),
            profile("alpha-dev", "us-east-1"),
        ]
        result = initialize_project(
            start_dir=tmp_path,
            bindings_path=bindings_path,
            stdin=stdin,
            stdout=StringIO(),
            stderr=StringIO(),
            identity_provider=lambda name: identities[name],
            profiles_loader=lambda: profiles,
        )

        assert result.project == "payment-service"
        assert [item.name for item in result.environments] == ["dev", "prod"]
        config = load_project_config(tmp_path / ".awsui.yaml")
        assert config.contexts["dev"].account == "111111111111"
        assert config.contexts["dev"].protected is False
        assert config.contexts["prod"].account == "999999999999"
        assert config.contexts["prod"].protected is True
        bindings = load_bindings(bindings_path)
        assert bindings.get_profile("payment-service", "dev") == "alpha-dev"
        assert bindings.get_profile("payment-service", "prod") == "zeta-prod"
        shared = (tmp_path / ".awsui.yaml").read_text(encoding="utf-8")
        assert "alpha-dev" not in shared
        assert "zeta-prod" not in shared

    def test_default_authentication_uses_sanitized_profile_environment(self, tmp_path):
        captured = {}

        def authenticate(name, **kwargs):
            captured["name"] = name
            captured.update(kwargs)
            return {"Account": "999999999999"}

        with patch(
            "awsui.project.initialization.authenticate_profile",
            side_effect=authenticate,
        ):
            initialize_project(
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
                base_environment={
                    "PATH": "/bin",
                    "AWS_ACCESS_KEY_ID": "must-not-leak",
                    "AWS_SESSION_TOKEN": "must-not-leak",
                },
                stdin=StringIO("\nprod\n1\n\ny\n\n"),
                stdout=StringIO(),
                stderr=StringIO(),
                profiles_loader=lambda: [profile("company-prod", "ap-northeast-1")],
            )

        environment = captured["environment"]
        assert environment["AWS_PROFILE"] == "company-prod"
        assert environment["AWS_REGION"] == "ap-northeast-1"
        assert environment["AWS_DEFAULT_REGION"] == "ap-northeast-1"
        assert environment["PATH"] == "/bin"
        assert "AWS_ACCESS_KEY_ID" not in environment
        assert "AWS_SESSION_TOKEN" not in environment

    def test_existing_configuration_is_never_overwritten(self, tmp_path):
        config_path = tmp_path / ".awsui.yaml"
        config_path.write_text("existing\n", encoding="utf-8")

        with pytest.raises(InitCommandError, match="already exists"):
            initialize_project(start_dir=tmp_path)

        assert config_path.read_text(encoding="utf-8") == "existing\n"

    def test_cancellation_writes_nothing(self, tmp_path):
        with pytest.raises(InitCommandCancelled):
            initialize_project(
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("\nprod\nq\n"),
                stdout=StringIO(),
                stderr=StringIO(),
                profiles_loader=lambda: [profile("company-prod", "ap-northeast-1")],
            )

        assert not (tmp_path / ".awsui.yaml").exists()
        assert not (tmp_path / "bindings.json").exists()

    def test_identity_failure_writes_nothing(self, tmp_path):
        with pytest.raises(InitCommandError, match="unable to retrieve"):
            initialize_project(
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("\nprod\n1\n\nn\n"),
                stdout=StringIO(),
                stderr=StringIO(),
                identity_provider=lambda _name: None,
                profiles_loader=lambda: [profile("company-prod", "ap-northeast-1")],
            )

        assert not (tmp_path / ".awsui.yaml").exists()

    def test_binding_failure_reports_recoverable_shared_config(self, tmp_path):
        bindings_path = tmp_path / "bindings.json"
        write_error = LocalBindingsWriteError(bindings_path, "disk full")

        with (
            patch(
                "awsui.project.initialization.save_bindings",
                side_effect=write_error,
            ),
            pytest.raises(
                InitCommandError,
                match="project configuration was created.*local bindings",
            ),
        ):
            initialize_project(
                start_dir=tmp_path,
                bindings_path=bindings_path,
                stdin=StringIO("\nprod\n1\n\nn\n\n"),
                stdout=StringIO(),
                stderr=StringIO(),
                identity_provider=lambda _name: {"Account": "999999999999"},
                profiles_loader=lambda: [profile("company-prod", "ap-northeast-1")],
            )

        assert (tmp_path / ".awsui.yaml").is_file()

    def test_creates_first_profile_inside_init(self, tmp_path):
        created = profile("payment-service-dev", "ap-northeast-1")
        state = {"created": False}
        commands = []

        def profiles_loader():
            return [created] if state["created"] else []

        def command_runner(command, **_kwargs):
            commands.append(command)
            state["created"] = True
            return 0

        result = initialize_project(
            start_dir=tmp_path,
            bindings_path=tmp_path / "bindings.json",
            stdin=StringIO("payment-service\ndev\nc\n1\n\n\nn\n\n"),
            stdout=StringIO(),
            stderr=StringIO(),
            identity_provider=lambda _name: {"Account": "111111111111"},
            profiles_loader=profiles_loader,
            command_runner=command_runner,
            cli_info_provider=lambda: AwsCliInfo(
                version=(2, 34, 15),
                raw="aws-cli/2.34.15",
            ),
        )

        assert result.environments[0].profile == "payment-service-dev"
        assert commands[0] == [
            "aws",
            "configure",
            "sso",
            "--profile",
            "payment-service-dev",
        ]
