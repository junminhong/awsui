"""Tests for the headless project initialization use case."""

from unittest.mock import patch

import pytest

from awsui.project.bindings import LocalBindingsWriteError, load_bindings
from awsui.project.config import load_project_config
from awsui.project.initialization import (
    InitializedEnvironment,
    ProjectBindingsWriteError,
    ProjectInitializationError,
    commit_project_initialization,
    resolve_initialization_target,
    verify_initialization_environment,
)


def test_resolves_default_project_and_rejects_existing_config(tmp_path):
    target = resolve_initialization_target(tmp_path)
    assert target.default_project == tmp_path.name
    assert target.config_path == tmp_path / ".awsui.yaml"

    target.config_path.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ProjectInitializationError, match="already exists"):
        resolve_initialization_target(tmp_path)


def test_verification_uses_sanitized_profile_environment(tmp_path):
    captured = {}

    def authenticate(profile, **kwargs):
        captured["profile"] = profile
        captured.update(kwargs)
        return {
            "Account": "111111111111",
            "Arn": "arn:aws:sts::111111111111:assumed-role/Developer/test",
        }

    with patch(
        "awsui.project.initialization.authenticate_profile",
        side_effect=authenticate,
    ):
        verified = verify_initialization_environment(
            name="qa",
            profile="company-qa",
            region="ap-northeast-1",
            protected=False,
            base_environment={
                "PATH": "/bin",
                "AWS_ACCESS_KEY_ID": "must-not-leak",
                "AWS_SESSION_TOKEN": "must-not-leak",
            },
        )

    assert verified.account == "111111111111"
    assert verified.principal_arn is not None
    environment = captured["environment"]
    assert environment["AWS_PROFILE"] == "company-qa"
    assert environment["AWS_REGION"] == "ap-northeast-1"
    assert environment["PATH"] == "/bin"
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "AWS_SESSION_TOKEN" not in environment


def test_commit_separates_shared_contexts_from_local_profiles(tmp_path):
    bindings_path = tmp_path / "bindings.json"
    environments = (
        InitializedEnvironment(
            "dev",
            "alice-dev",
            "111111111111",
            "ap-northeast-1",
            False,
        ),
        InitializedEnvironment(
            "qa",
            "alice-qa",
            "222222222222",
            "ap-northeast-1",
            False,
        ),
    )

    result = commit_project_initialization(
        project="payment-service",
        environments=environments,
        start_dir=tmp_path,
        bindings_path=bindings_path,
    )

    config = load_project_config(result.config_path)
    assert list(config.contexts) == ["dev", "qa"]
    shared = result.config_path.read_text(encoding="utf-8")
    assert "alice-dev" not in shared
    assert "alice-qa" not in shared
    bindings = load_bindings(bindings_path)
    assert bindings.get_profile("payment-service", "dev") == "alice-dev"
    assert bindings.get_profile("payment-service", "qa") == "alice-qa"


def test_bindings_failure_reports_recoverable_shared_config(tmp_path):
    bindings_path = tmp_path / "bindings.json"
    environment = InitializedEnvironment(
        "prod",
        "company-prod",
        "999999999999",
        "ap-northeast-1",
        True,
    )
    error = LocalBindingsWriteError(bindings_path, "disk full")

    with (
        patch("awsui.project.initialization.save_bindings", side_effect=error),
        pytest.raises(ProjectBindingsWriteError) as raised,
    ):
        commit_project_initialization(
            project="payment-service",
            environments=(environment,),
            start_dir=tmp_path,
            bindings_path=bindings_path,
        )

    assert raised.value.config_path == tmp_path / ".awsui.yaml"
    assert raised.value.config_path.is_file()
