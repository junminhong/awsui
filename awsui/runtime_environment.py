"""Deterministic AWS environment construction for child processes."""

from collections.abc import Mapping

from .context.resolution import ResolvedContext


_CREDENTIAL_ENVIRONMENT_VARIABLES = frozenset(
    {
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
    }
)
_BEARER_TOKEN_PREFIX = "AWS_BEARER_TOKEN_"


def build_aws_environment(
    context: ResolvedContext,
    *,
    base_environment: Mapping[str, str],
) -> dict[str, str]:
    """Build a sanitized environment for the selected project context."""
    return build_profile_environment(
        context.profile,
        context.region,
        base_environment=base_environment,
    )


def build_profile_environment(
    profile: str,
    region: str,
    *,
    base_environment: Mapping[str, str],
) -> dict[str, str]:
    """Build a sanitized environment for an explicit profile and region."""
    environment = sanitize_credential_environment(base_environment)
    environment["AWS_PROFILE"] = profile
    environment["AWS_REGION"] = region
    environment["AWS_DEFAULT_REGION"] = region
    return environment


def sanitize_credential_environment(
    base_environment: Mapping[str, str],
) -> dict[str, str]:
    """Remove direct credential sources while preserving AWS config paths."""
    return {
        key: value
        for key, value in base_environment.items()
        if not _is_credential_override(key)
    }


def _is_credential_override(name: str) -> bool:
    return name in _CREDENTIAL_ENVIRONMENT_VARIABLES or name.startswith(
        _BEARER_TOKEN_PREFIX
    )
