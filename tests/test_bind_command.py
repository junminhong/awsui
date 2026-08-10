"""Tests for the interactive profile binding command."""

from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from awsui.aws_cli import AwsCliInfo
from awsui.bind_command import (
    BindCommandCancelled,
    BindCommandError,
    bind_environment,
)
from awsui.bindings import (
    LocalBindingsWriteError,
    load_bindings,
    save_bindings,
)


PROJECT_CONFIG = """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: ap-northeast-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
    protected: true
"""

AWS_CONFIG = """\
[profile zeta-prod]
sso_session = company
sso_account_id = 999999999999
sso_role_name = AdministratorAccess
region = ap-northeast-1

[profile alpha-dev]
region = us-east-1
"""


def prepare_project(tmp_path: Path, config: str = PROJECT_CONFIG) -> Path:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".awsui.yaml").write_text(config, encoding="utf-8")
    nested = project_dir / "src"
    nested.mkdir()
    return nested


def prepare_aws_profiles(
    tmp_path: Path,
    monkeypatch,
    config: str = AWS_CONFIG,
) -> None:
    aws_dir = tmp_path / "aws"
    aws_dir.mkdir(exist_ok=True)
    config_path = aws_dir / "config"
    credentials_path = aws_dir / "credentials"
    config_path.write_text(config, encoding="utf-8")
    credentials_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_path))


class TestBindEnvironment:
    """Tests for successful binding interactions."""

    def test_selects_profile_by_number_and_persists(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"
        stdout = StringIO()

        with (
            patch("awsui.aws_cli.get_caller_identity") as mock_identity,
            patch("awsui.aws_cli.sso_login") as mock_login,
        ):
            result = bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=bindings_path,
                stdin=StringIO("2\n"),
                stdout=stdout,
            )

        assert result.project == "payment-service"
        assert result.environment == "prod"
        assert result.profile == "zeta-prod"
        assert result.previous_profile is None
        assert result.changed is True
        assert (
            load_bindings(bindings_path).get_profile("payment-service", "prod")
            == "zeta-prod"
        )
        mock_identity.assert_not_called()
        mock_login.assert_not_called()

        output = stdout.getvalue()
        assert "payment-service · PROD · PROTECTED" in output
        assert "Expected account: 999999999999" in output
        assert "Region: ap-northeast-1" in output
        assert output.index("alpha-dev") < output.index("zeta-prod")
        assert "verified" not in output.casefold()

    def test_selects_profile_by_exact_name(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"

        result = bind_environment(
            "dev",
            start_dir=start_dir,
            bindings_path=bindings_path,
            stdin=StringIO("zeta-prod\n"),
            stdout=StringIO(),
        )

        assert result.profile == "zeta-prod"
        assert result.changed is True

    def test_invalid_selection_retries(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        stdout = StringIO()

        result = bind_environment(
            "dev",
            start_dir=start_dir,
            bindings_path=tmp_path / "bindings.json",
            stdin=StringIO("99\nmissing\n1\n"),
            stdout=stdout,
        )

        assert result.profile == "alpha-dev"
        assert stdout.getvalue().count("Invalid selection.") == 2

    def test_enter_keeps_current_binding_without_writing(
        self,
        tmp_path,
        monkeypatch,
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"
        bindings = load_bindings(bindings_path).with_binding(
            "payment-service",
            "prod",
            "zeta-prod",
        )
        save_bindings(bindings)
        stdout = StringIO()

        with patch("awsui.bind_command.save_bindings") as mock_save:
            result = bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=bindings_path,
                stdin=StringIO("\n"),
                stdout=stdout,
            )

        assert result.profile == "zeta-prod"
        assert result.previous_profile == "zeta-prod"
        assert result.changed is False
        mock_save.assert_not_called()
        assert "zeta-prod (sso · ap-northeast-1) [current]" in stdout.getvalue()

    def test_selecting_another_profile_replaces_current_binding(
        self,
        tmp_path,
        monkeypatch,
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"
        bindings = load_bindings(bindings_path).with_binding(
            "payment-service",
            "prod",
            "zeta-prod",
        )
        save_bindings(bindings)

        result = bind_environment(
            "prod",
            start_dir=start_dir,
            bindings_path=bindings_path,
            stdin=StringIO("1\n"),
            stdout=StringIO(),
        )

        assert result.profile == "alpha-dev"
        assert result.previous_profile == "zeta-prod"
        assert result.changed is True
        assert (
            load_bindings(bindings_path).get_profile("payment-service", "prod")
            == "alpha-dev"
        )

    def test_missing_current_profile_is_reported_and_replaced(
        self,
        tmp_path,
        monkeypatch,
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"
        bindings = load_bindings(bindings_path).with_binding(
            "payment-service",
            "prod",
            "removed-profile",
        )
        save_bindings(bindings)
        stdout = StringIO()

        result = bind_environment(
            "prod",
            start_dir=start_dir,
            bindings_path=bindings_path,
            stdin=StringIO("1\n"),
            stdout=stdout,
        )

        assert result.previous_profile == "removed-profile"
        assert result.profile == "alpha-dev"
        assert "was not found in local AWS profiles" in stdout.getvalue()

    def test_creates_and_binds_profile_without_leaving_workflow(
        self,
        tmp_path,
        monkeypatch,
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch, config="")
        created = {
            "name": "payment-service-dev",
            "kind": "sso",
            "account": "111111111111",
            "role": "Developer",
            "region": "ap-northeast-1",
            "session": "company",
            "source": str(tmp_path / "aws" / "config"),
        }
        state = {"created": False}
        commands = []

        def profiles_loader():
            return [created] if state["created"] else []

        def command_runner(command, **_kwargs):
            commands.append(command)
            state["created"] = True
            return 0

        result = bind_environment(
            "dev",
            start_dir=start_dir,
            bindings_path=tmp_path / "bindings.json",
            stdin=StringIO("c\n1\n\n"),
            stdout=StringIO(),
            profiles_loader=profiles_loader,
            command_runner=command_runner,
            cli_info_provider=lambda: AwsCliInfo(
                version=(2, 34, 15),
                raw="aws-cli/2.34.15",
            ),
        )

        assert result.profile == "payment-service-dev"
        assert commands == [
            [
                "aws",
                "configure",
                "sso",
                "--profile",
                "payment-service-dev",
            ]
        ]


class TestBindCancellation:
    """Tests for explicit and stream-based cancellation."""

    @pytest.mark.parametrize("selection", ["q\n", "QUIT\n"])
    def test_cancel_selection(self, tmp_path, monkeypatch, selection):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)

        with pytest.raises(BindCommandCancelled, match="binding cancelled"):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO(selection),
                stdout=StringIO(),
            )

    def test_end_of_input_cancels(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)

        with pytest.raises(BindCommandCancelled, match="input closed"):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO(""),
                stdout=StringIO(),
            )


class TestBindFailures:
    """Tests for fail-closed binding errors."""

    def test_missing_project_config(self, tmp_path, monkeypatch):
        prepare_aws_profiles(tmp_path, monkeypatch)

        with pytest.raises(BindCommandError, match=r"\.awsui\.yaml was not found"):
            bind_environment(
                "prod",
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("1\n"),
                stdout=StringIO(),
            )

    def test_invalid_project_config(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path, "version: 1\n")
        prepare_aws_profiles(tmp_path, monkeypatch)

        with pytest.raises(BindCommandError, match="missing required fields"):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("1\n"),
                stdout=StringIO(),
            )

    def test_unknown_environment_lists_available_contexts(
        self,
        tmp_path,
        monkeypatch,
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)

        with pytest.raises(
            BindCommandError,
            match="available environments: dev, prod",
        ):
            bind_environment(
                "staging",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("1\n"),
                stdout=StringIO(),
            )

    def test_no_local_profiles_can_enter_creation_or_cancel(
        self, tmp_path, monkeypatch
    ):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch, config="")

        output = StringIO()
        with pytest.raises(BindCommandCancelled, match="binding cancelled"):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("q\n"),
                stdout=output,
            )
        assert "No local AWS profiles found" in output.getvalue()

    def test_malformed_aws_config(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch, config="[broken")

        with pytest.raises(
            BindCommandError,
            match="unable to read local AWS profiles",
        ):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=tmp_path / "bindings.json",
                stdin=StringIO("1\n"),
                stdout=StringIO(),
            )

    def test_corrupt_bindings_file(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"
        bindings_path.write_text("{", encoding="utf-8")

        with pytest.raises(BindCommandError, match="invalid JSON"):
            bind_environment(
                "prod",
                start_dir=start_dir,
                bindings_path=bindings_path,
                stdin=StringIO("1\n"),
                stdout=StringIO(),
            )

        assert bindings_path.read_text(encoding="utf-8") == "{"

    def test_binding_write_failure(self, tmp_path, monkeypatch):
        start_dir = prepare_project(tmp_path)
        prepare_aws_profiles(tmp_path, monkeypatch)
        bindings_path = tmp_path / "bindings.json"

        with patch(
            "awsui.bind_command.save_bindings",
            side_effect=LocalBindingsWriteError(
                bindings_path,
                "write failed",
            ),
        ):
            with pytest.raises(BindCommandError, match="write failed"):
                bind_environment(
                    "prod",
                    start_dir=start_dir,
                    bindings_path=bindings_path,
                    stdin=StringIO("1\n"),
                    stdout=StringIO(),
                )

        assert not bindings_path.exists()
