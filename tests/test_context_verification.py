"""Tests for fail-closed AWS context identity verification."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from awsui.context_engine import ResolvedContext
from awsui.context_verification import (
    AccountMismatchError,
    AuthenticatedIdentity,
    IdentityUnavailableError,
    InvalidIdentityError,
    VerifiedContext,
    authenticate_identity,
    verify_context,
)
from awsui.profile_catalog import ProfileCatalog


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


class TestVerifyContext:
    """Tests for successful AWS account verification."""

    def test_matching_account_returns_verified_context(self):
        context = resolved_context()
        provider = Mock(
            return_value={
                "Account": "999999999999",
                "Arn": "arn:aws:sts::999999999999:assumed-role/Admin/user",
                "UserId": "AROEXAMPLE:user",
            }
        )

        verified = verify_context(context, identity_provider=provider)

        assert verified == VerifiedContext(
            resolved=context,
            actual_account="999999999999",
            principal_arn=("arn:aws:sts::999999999999:assumed-role/Admin/user"),
        )
        assert verified.resolved is context
        provider.assert_called_once_with("company-prod")

    def test_verified_context_is_immutable(self):
        context = resolved_context()
        verified = verify_context(
            context,
            identity_provider=lambda _profile: {"Account": "999999999999"},
        )

        with pytest.raises(FrozenInstanceError):
            verified.actual_account = "111111111111"  # type: ignore[misc]

    @patch("awsui.context_verification.authenticate_profile")
    def test_uses_default_identity_provider(self, mock_authenticate):
        mock_authenticate.return_value = {"Account": "999999999999"}

        verified = verify_context(resolved_context())

        assert verified.actual_account == "999999999999"
        mock_authenticate.assert_called_once_with("company-prod")

    @patch("awsui.profile_authentication.sso_login")
    @patch("awsui.profile_authentication.get_caller_identity")
    @patch("awsui.profile_authentication.load_profile_catalog")
    def test_default_provider_retries_after_sso_login(
        self,
        mock_catalog,
        mock_identity,
        mock_login,
    ):
        mock_catalog.return_value = ProfileCatalog.from_profiles(
            [
                {
                    "name": "company-prod",
                    "kind": "sso",
                    "account": "999999999999",
                    "role": "Admin",
                    "region": "ap-northeast-1",
                    "session": "company",
                    "source": "/home/user/.aws/config",
                }
            ]
        )
        mock_identity.side_effect = [None, {"Account": "999999999999"}]
        mock_login.return_value = True

        verified = verify_context(resolved_context())

        assert verified.actual_account == "999999999999"
        assert mock_identity.call_count == 2
        mock_login.assert_called_once_with(
            "company-prod",
            cancel_check=None,
            environment=None,
            login_output=None,
        )

    def test_authenticate_identity_normalizes_account(self):
        identity = authenticate_identity(
            "company-prod",
            identity_provider=lambda _profile: {
                "Account": "999999999999",
                "Arn": "arn:aws:iam::999999999999:role/Admin",
            },
        )

        assert identity == AuthenticatedIdentity(
            profile="company-prod",
            account="999999999999",
            principal_arn="arn:aws:iam::999999999999:role/Admin",
        )

    @pytest.mark.parametrize("arn", [None, "", "   ", 123])
    def test_optional_principal_arn_is_omitted_when_unusable(self, arn):
        identity = authenticate_identity(
            "company-prod",
            identity_provider=lambda _profile: {
                "Account": "999999999999",
                "Arn": arn,
            },
        )

        assert identity.principal_arn is None


class TestVerificationFailures:
    """Tests for verification failures that must block a verified result."""

    def test_unavailable_identity_fails_closed(self):
        context = resolved_context()

        with pytest.raises(IdentityUnavailableError) as exc_info:
            verify_context(context, identity_provider=lambda _profile: None)

        error = exc_info.value
        assert error.profile == "company-prod"
        assert "unable to retrieve AWS caller identity" in str(error)

    @pytest.mark.parametrize(
        ("identity", "reason"),
        [
            ({}, "Account must be an ASCII 12-digit string"),
            ({"Account": 999999999999}, "Account must be an ASCII 12-digit string"),
            ({"Account": "123"}, "Account must be an ASCII 12-digit string"),
            (
                {"Account": "９９９９９９９９９９９９"},
                "Account must be an ASCII 12-digit string",
            ),
        ],
    )
    def test_invalid_account_fails_closed(self, identity, reason):
        with pytest.raises(InvalidIdentityError) as exc_info:
            verify_context(
                resolved_context(),
                identity_provider=lambda _profile: identity,
            )

        error = exc_info.value
        assert error.profile == "company-prod"
        assert error.reason == reason

    def test_non_object_identity_fails_closed(self):
        with pytest.raises(InvalidIdentityError) as exc_info:
            verify_context(
                resolved_context(),
                identity_provider=lambda _profile: [],  # type: ignore[return-value]
            )

        assert exc_info.value.reason == "response must be an object"

    def test_account_mismatch_exposes_diagnostic_fields(self):
        with pytest.raises(AccountMismatchError) as exc_info:
            verify_context(
                resolved_context(),
                identity_provider=lambda _profile: {"Account": "111111111111"},
            )

        error = exc_info.value
        assert error.project == "payment-service"
        assert error.environment == "prod"
        assert error.profile == "company-prod"
        assert error.expected_account == "999999999999"
        assert error.actual_account == "111111111111"
        assert "expected 999999999999, authenticated 111111111111" in str(error)
