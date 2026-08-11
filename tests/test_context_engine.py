"""Tests for deterministic project context resolution."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import pytest

from awsui.bindings import load_bindings, save_bindings
from awsui.context_engine import (
    BindingNotFoundError,
    ContextSourceError,
    EnvironmentNotFoundError,
    ResolvedContext,
    resolve_context,
)
from awsui.project_config import (
    ProjectConfigNotFoundError,
    ProjectConfigValidationError,
)


PROJECT_CONFIG = """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
    protected: true
"""


def write_project_config(directory: Path, content: str = PROJECT_CONFIG) -> Path:
    path = directory / ".awsui.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def write_binding(
    path: Path,
    *,
    project: str = "payment-service",
    environment: str = "prod",
    profile: str = "company-prod",
) -> None:
    bindings = load_bindings(path).with_binding(
        project,
        environment,
        profile,
    )
    save_bindings(bindings)


class TestResolveContext:
    """Tests for successful local context resolution."""

    def test_resolves_project_environment_and_binding(self, tmp_path):
        project_path = write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)

        context = resolve_context(
            "prod",
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

        assert context == ResolvedContext(
            project="payment-service",
            environment="prod",
            expected_account="999999999999",
            region="ap-northeast-1",
            profile="company-prod",
            protected=True,
            project_config_path=project_path.resolve(),
            bindings_path=bindings_path.resolve(),
        )

    def test_resolves_non_protected_environment(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(
            bindings_path,
            environment="dev",
            profile="company-dev",
        )

        context = resolve_context(
            "dev",
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

        assert context.expected_account == "111111111111"
        assert context.region == "us-east-1"
        assert context.profile == "company-dev"
        assert context.protected is False

    def test_resolves_qa_as_a_first_class_environment(self, tmp_path):
        qa_config = PROJECT_CONFIG.replace(
            "  prod:\n",
            '  qa:\n    account: "222222222222"\n    region: ap-southeast-1\n  prod:\n',
        )
        write_project_config(tmp_path, qa_config)
        bindings_path = tmp_path / "bindings.json"
        write_binding(
            bindings_path,
            environment="qa",
            profile="company-qa",
        )

        context = resolve_context(
            "qa",
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

        assert context.environment == "qa"
        assert context.expected_account == "222222222222"
        assert context.region == "ap-southeast-1"
        assert context.profile == "company-qa"
        assert context.protected is False

    def test_uses_nearest_parent_project_config(self, tmp_path):
        write_project_config(
            tmp_path,
            PROJECT_CONFIG.replace("payment-service", "outer-service"),
        )
        project = tmp_path / "project"
        project.mkdir()
        nearest = write_project_config(project)
        nested = project / "src" / "module"
        nested.mkdir(parents=True)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)

        context = resolve_context(
            "prod",
            start_dir=nested,
            bindings_path=bindings_path,
        )

        assert context.project == "payment-service"
        assert context.project_config_path == nearest.resolve()

    def test_resolved_context_is_immutable(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)
        context = resolve_context(
            "prod",
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

        with pytest.raises(FrozenInstanceError):
            context.profile = "other-profile"  # type: ignore[misc]

    def test_resolved_context_has_no_verification_fields(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)

        context = resolve_context(
            "prod",
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

        assert not hasattr(context, "verified")
        assert not hasattr(context, "actual_account")
        assert not hasattr(context, "arn")

    def test_resolution_does_not_read_profiles_or_call_aws(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)

        with (
            patch("awsui.config.parse_profiles") as mock_profiles,
            patch("awsui.aws_cli.get_caller_identity") as mock_identity,
            patch("awsui.aws_cli.sso_login") as mock_login,
        ):
            context = resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=bindings_path,
            )

        assert context.profile == "company-prod"
        mock_profiles.assert_not_called()
        mock_identity.assert_not_called()
        mock_login.assert_not_called()


class TestResolutionFailures:
    """Tests for fail-closed context resolution errors."""

    def test_environment_is_case_sensitive(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(bindings_path)

        with pytest.raises(EnvironmentNotFoundError) as exc_info:
            resolve_context(
                "PROD",
                start_dir=tmp_path,
                bindings_path=bindings_path,
            )

        error = exc_info.value
        assert error.project == "payment-service"
        assert error.environment == "PROD"
        assert error.available_environments == ("dev", "prod")
        assert "available environments: dev, prod" in str(error)

    def test_missing_binding_in_existing_store(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        write_binding(
            bindings_path,
            environment="dev",
            profile="company-dev",
        )

        with pytest.raises(BindingNotFoundError) as exc_info:
            resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=bindings_path,
            )

        error = exc_info.value
        assert error.project == "payment-service"
        assert error.environment == "prod"
        assert "run 'awsui bind prod'" in str(error)

    def test_missing_bindings_file_is_unbound(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "missing" / "bindings.json"

        with pytest.raises(BindingNotFoundError, match="awsui bind prod"):
            resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=bindings_path,
            )

        assert not bindings_path.exists()

    def test_missing_project_config_is_source_error(self, tmp_path):
        with pytest.raises(ContextSourceError) as exc_info:
            resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
            )

        error = exc_info.value
        assert error.source == "project configuration"
        assert error.path == tmp_path.resolve()
        assert isinstance(error.__cause__, ProjectConfigNotFoundError)

    def test_invalid_project_config_is_source_error(self, tmp_path):
        config_path = write_project_config(tmp_path, "version: 1\n")

        with pytest.raises(ContextSourceError) as exc_info:
            resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=tmp_path / "bindings.json",
            )

        error = exc_info.value
        assert error.source == "project configuration"
        assert error.path == config_path.resolve()
        assert isinstance(error.__cause__, ProjectConfigValidationError)
        assert "missing required fields" in str(error)

    def test_corrupt_bindings_is_source_error(self, tmp_path):
        write_project_config(tmp_path)
        bindings_path = tmp_path / "bindings.json"
        bindings_path.write_text("{", encoding="utf-8")

        with pytest.raises(ContextSourceError) as exc_info:
            resolve_context(
                "prod",
                start_dir=tmp_path,
                bindings_path=bindings_path,
            )

        error = exc_info.value
        assert error.source == "local bindings"
        assert error.path == bindings_path.resolve()
        assert "invalid JSON" in str(error)
        assert bindings_path.read_text(encoding="utf-8") == "{"

    def test_unknown_environment_does_not_read_bindings(self, tmp_path):
        write_project_config(tmp_path)

        with patch("awsui.context_engine.load_bindings") as mock_load:
            with pytest.raises(EnvironmentNotFoundError):
                resolve_context(
                    "staging",
                    start_dir=tmp_path,
                    bindings_path=tmp_path / "bindings.json",
                )

        mock_load.assert_not_called()
