"""Preparation of verified, deterministic AWS process runtimes."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TextIO

from .context_engine import ResolvedContext, resolve_context
from .context_verification import IdentityProvider, VerifiedContext, verify_context
from .profile_authentication import authenticate_profile
from .runtime_environment import build_aws_environment


@dataclass(frozen=True, slots=True)
class VerifiedRuntime:
    """A verified context paired with its immutable child environment."""

    verified: VerifiedContext
    environment: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(self.environment)),
        )


def prepare_context_runtime(
    environment_name: str,
    *,
    base_environment: Mapping[str, str],
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
    identity_provider: IdentityProvider | None = None,
    login_output: TextIO | None = None,
) -> VerifiedRuntime:
    """Resolve, sanitize, authenticate, and verify a project environment."""
    resolved = resolve_context(
        environment_name,
        start_dir=start_dir,
        bindings_path=bindings_path,
    )
    return prepare_resolved_runtime(
        resolved,
        base_environment=base_environment,
        identity_provider=identity_provider,
        login_output=login_output,
    )


def prepare_resolved_runtime(
    resolved: ResolvedContext,
    *,
    base_environment: Mapping[str, str],
    identity_provider: IdentityProvider | None = None,
    login_output: TextIO | None = None,
) -> VerifiedRuntime:
    """Sanitize, authenticate, and verify an already resolved context."""
    runtime_environment = build_aws_environment(
        resolved,
        base_environment=base_environment,
    )

    provider = identity_provider
    if provider is None:

        def provider(profile: str) -> Mapping[str, object] | None:
            return authenticate_profile(
                profile,
                environment=runtime_environment,
                login_output=login_output,
            )

    verified = verify_context(
        resolved,
        identity_provider=provider,
    )
    return VerifiedRuntime(
        verified=verified,
        environment=runtime_environment,
    )
