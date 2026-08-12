"""Tests for verified deterministic AWS runtime preparation."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import pytest

from awsui.context.resolution import ResolvedContext
from awsui.context.runtime import VerifiedRuntime, prepare_context_runtime


def resolved_context() -> ResolvedContext:
    return ResolvedContext(
        project="payment-service",
        environment="prod",
        expected_account="999999999999",
        region="ap-northeast-1",
        profile="company-prod",
        protected=True,
        project_config_path=Path("/project/.awsui.yaml"),
        bindings_path=Path("/config/awsui/bindings.json"),
    )


class TestPrepareContextRuntime:
    @patch("awsui.context.runtime.authenticate_profile")
    @patch("awsui.context.runtime.resolve_context")
    def test_uses_same_sanitized_environment_for_authentication(
        self,
        mock_resolve,
        mock_authenticate,
    ):
        resolved = resolved_context()
        mock_resolve.return_value = resolved
        mock_authenticate.return_value = {"Account": "999999999999"}
        base = {
            "PATH": "/usr/bin",
            "AWS_ACCESS_KEY_ID": "must-not-leak",
            "AWS_SECRET_ACCESS_KEY": "must-not-leak",
            "AWS_CONFIG_FILE": "/custom/config",
        }

        runtime = prepare_context_runtime(
            "prod",
            base_environment=base,
            start_dir=Path("/project"),
            bindings_path=Path("/bindings.json"),
        )

        assert runtime.verified.resolved is resolved
        assert runtime.verified.actual_account == "999999999999"
        assert runtime.environment["AWS_PROFILE"] == "company-prod"
        assert runtime.environment["AWS_REGION"] == "ap-northeast-1"
        assert runtime.environment["AWS_CONFIG_FILE"] == "/custom/config"
        assert "AWS_ACCESS_KEY_ID" not in runtime.environment
        assert "AWS_SECRET_ACCESS_KEY" not in runtime.environment
        mock_resolve.assert_called_once_with(
            "prod",
            start_dir=Path("/project"),
            bindings_path=Path("/bindings.json"),
        )
        authentication_environment = mock_authenticate.call_args.kwargs["environment"]
        assert authentication_environment == dict(runtime.environment)
        assert mock_authenticate.call_args.kwargs["login_output"] is None

    @patch("awsui.context.runtime.resolve_context")
    def test_injected_identity_provider_is_used(self, mock_resolve):
        mock_resolve.return_value = resolved_context()
        calls: list[str] = []

        def provider(profile: str):
            calls.append(profile)
            return {"Account": "999999999999"}

        runtime = prepare_context_runtime(
            "prod",
            base_environment={},
            identity_provider=provider,
        )

        assert runtime.verified.actual_account == "999999999999"
        assert calls == ["company-prod"]

    @patch("awsui.context.runtime.resolve_context")
    def test_runtime_environment_is_immutable(self, mock_resolve):
        mock_resolve.return_value = resolved_context()
        runtime = prepare_context_runtime(
            "prod",
            base_environment={},
            identity_provider=lambda _profile: {"Account": "999999999999"},
        )

        assert isinstance(runtime, VerifiedRuntime)
        with pytest.raises(TypeError):
            runtime.environment["AWS_PROFILE"] = "other"  # type: ignore[index]
        with pytest.raises(FrozenInstanceError):
            runtime.environment = {}  # type: ignore[misc]
