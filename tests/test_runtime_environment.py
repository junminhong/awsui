"""Tests for deterministic child-process AWS environments."""

from pathlib import Path
from types import MappingProxyType

import pytest

from awsui.context_engine import ResolvedContext
from awsui.runtime_environment import build_aws_environment


CREDENTIAL_ENVIRONMENT_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_BEARER_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SECURITY_TOKEN",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
)


def resolved_context() -> ResolvedContext:
    return ResolvedContext(
        project="payment-service",
        environment="prod",
        expected_account="999999999999",
        region="ap-northeast-1",
        profile="company-prod",
        protected=True,
        project_config_path=Path("/project/.awsui.yaml"),
        bindings_path=Path("/home/user/.config/awsui/bindings.json"),
    )


class TestBuildAwsEnvironment:
    """Tests for deterministic context values and environment preservation."""

    def test_sets_selected_profile_and_regions(self):
        environment = build_aws_environment(
            resolved_context(),
            base_environment={
                "AWS_PROFILE": "wrong-profile",
                "AWS_REGION": "us-west-2",
                "AWS_DEFAULT_REGION": "eu-west-1",
            },
        )

        assert environment["AWS_PROFILE"] == "company-prod"
        assert environment["AWS_REGION"] == "ap-northeast-1"
        assert environment["AWS_DEFAULT_REGION"] == "ap-northeast-1"

    def test_empty_base_contains_only_required_context_values(self):
        environment = build_aws_environment(
            resolved_context(),
            base_environment={},
        )

        assert environment == {
            "AWS_PROFILE": "company-prod",
            "AWS_REGION": "ap-northeast-1",
            "AWS_DEFAULT_REGION": "ap-northeast-1",
        }

    def test_preserves_non_credential_environment_values(self):
        base = {
            "PATH": "/usr/local/bin:/usr/bin",
            "HOME": "/home/developer",
            "AWS_CONFIG_FILE": "/custom/aws/config",
            "AWS_SHARED_CREDENTIALS_FILE": "/custom/aws/credentials",
            "AWS_CA_BUNDLE": "/custom/ca.pem",
            "AWS_RETRY_MODE": "adaptive",
            "AWS_EC2_METADATA_DISABLED": "true",
        }

        environment = build_aws_environment(
            resolved_context(),
            base_environment=base,
        )

        for key, value in base.items():
            assert environment[key] == value

    def test_accepts_read_only_mapping(self):
        base = MappingProxyType({"PATH": "/usr/bin"})

        environment = build_aws_environment(
            resolved_context(),
            base_environment=base,
        )

        assert environment["PATH"] == "/usr/bin"

    def test_returns_independent_dict_without_mutating_inputs(self):
        context = resolved_context()
        original_context = resolved_context()
        base = {"PATH": "/usr/bin", "AWS_PROFILE": "original"}
        original_base = dict(base)

        first = build_aws_environment(context, base_environment=base)
        second = build_aws_environment(context, base_environment=base)
        first["PATH"] = "/changed"

        assert first is not second
        assert second["PATH"] == "/usr/bin"
        assert base == original_base
        assert context == original_context


class TestCredentialIsolation:
    """Tests for credential sources that must not leak to children."""

    @pytest.mark.parametrize("variable", CREDENTIAL_ENVIRONMENT_VARIABLES)
    def test_removes_exact_credential_override(self, variable):
        environment = build_aws_environment(
            resolved_context(),
            base_environment={
                "PATH": "/usr/bin",
                variable: "sensitive-value",
            },
        )

        assert variable not in environment
        assert environment["PATH"] == "/usr/bin"

    @pytest.mark.parametrize(
        "variable",
        [
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_BEARER_TOKEN_FUTURE_SERVICE",
        ],
    )
    def test_removes_service_bearer_tokens(self, variable):
        environment = build_aws_environment(
            resolved_context(),
            base_environment={variable: "sensitive-value"},
        )

        assert variable not in environment

    def test_similarly_named_non_credential_variable_is_preserved(self):
        environment = build_aws_environment(
            resolved_context(),
            base_environment={"AWS_BEARER_TOKENS_ENABLED": "true"},
        )

        assert environment["AWS_BEARER_TOKENS_ENABLED"] == "true"
