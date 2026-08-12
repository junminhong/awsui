"""AWS identity verification for resolved project contexts."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import re

from ..profiles.authentication import (
    ProfileAuthenticationError,
    authenticate_profile,
)
from ..profiles.catalog import ProfileCatalogError
from .resolution import ResolvedContext


_ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}", re.ASCII)

IdentityProvider = Callable[[str], Mapping[str, object] | None]


def describe_principal(arn: str | None) -> tuple[str, str] | None:
    """Return a concise STS principal label and value for presentation."""
    if arn is None:
        return None
    resource = arn.split(":", 5)[-1]
    if resource.startswith("assumed-role/"):
        parts = resource.split("/")
        if len(parts) >= 3:
            return "Role", parts[-2]
    if resource.startswith("role/"):
        return "Role", resource.rsplit("/", 1)[-1]
    if resource.startswith("user/"):
        return "User", resource.rsplit("/", 1)[-1]
    if resource == "root":
        return "Principal", "root"
    return "Principal", arn


@dataclass(frozen=True, slots=True)
class VerifiedContext:
    """A resolved context whose authenticated AWS account was verified."""

    resolved: ResolvedContext
    actual_account: str
    principal_arn: str | None = None


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    """A normalized AWS caller identity for one local profile."""

    profile: str
    account: str
    principal_arn: str | None = None


class ContextVerificationError(Exception):
    """Base error for fail-closed AWS context verification."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class IdentityUnavailableError(ContextVerificationError):
    """Raised when AWS caller identity cannot be retrieved."""

    def __init__(self, profile: str) -> None:
        self.profile = profile
        super().__init__(
            f"unable to retrieve AWS caller identity for profile {profile!r}"
        )


class InvalidIdentityError(ContextVerificationError):
    """Raised when STS returns an unusable caller identity."""

    def __init__(self, profile: str, reason: str) -> None:
        self.profile = profile
        self.reason = reason
        super().__init__(
            f"invalid STS caller identity for profile {profile!r}: {reason}"
        )


class AuthenticationConfigurationError(ContextVerificationError):
    """Raised when a profile's authentication chain is invalid."""


class AccountMismatchError(ContextVerificationError):
    """Raised when authenticated and expected AWS accounts do not match."""

    def __init__(
        self,
        *,
        project: str,
        environment: str,
        profile: str,
        expected_account: str,
        actual_account: str,
    ) -> None:
        self.project = project
        self.environment = environment
        self.profile = profile
        self.expected_account = expected_account
        self.actual_account = actual_account
        super().__init__(
            f"AWS account mismatch for {project}/{environment}: "
            f"expected {expected_account}, authenticated {actual_account}"
        )


def verify_context(
    context: ResolvedContext,
    *,
    identity_provider: IdentityProvider | None = None,
) -> VerifiedContext:
    """Authenticate and verify that a resolved context targets its account."""
    identity = authenticate_identity(
        context.profile,
        identity_provider=identity_provider,
    )

    if identity.account != context.expected_account:
        raise AccountMismatchError(
            project=context.project,
            environment=context.environment,
            profile=context.profile,
            expected_account=context.expected_account,
            actual_account=identity.account,
        )

    return VerifiedContext(
        resolved=context,
        actual_account=identity.account,
        principal_arn=identity.principal_arn,
    )


def authenticate_identity(
    profile: str,
    *,
    identity_provider: IdentityProvider | None = None,
) -> AuthenticatedIdentity:
    """Authenticate a profile and normalize its STS account identity."""
    provider = authenticate_profile if identity_provider is None else identity_provider
    try:
        identity = provider(profile)
    except (ProfileAuthenticationError, ProfileCatalogError) as exc:
        raise AuthenticationConfigurationError(str(exc)) from exc

    if identity is None:
        raise IdentityUnavailableError(profile)

    if not isinstance(identity, Mapping):
        raise InvalidIdentityError(
            profile,
            "response must be an object",
        )

    actual_account = identity.get("Account")
    if not isinstance(actual_account, str) or not _ACCOUNT_ID_PATTERN.fullmatch(
        actual_account
    ):
        raise InvalidIdentityError(
            profile,
            "Account must be an ASCII 12-digit string",
        )

    raw_arn = identity.get("Arn")
    principal_arn = raw_arn.strip() if isinstance(raw_arn, str) else None
    if not principal_arn:
        principal_arn = None

    return AuthenticatedIdentity(
        profile=profile,
        account=actual_account,
        principal_arn=principal_arn,
    )
