"""Headless project initialization shared by CLI and Textual interfaces."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
from typing import TextIO

from .bindings import LocalBindingsError, load_bindings, save_bindings
from .context_verification import (
    AuthenticatedIdentity,
    IdentityProvider,
    authenticate_identity,
)
from .profile_authentication import authenticate_profile
from .project_config import (
    PROJECT_CONFIG_FILENAME,
    SUPPORTED_PROJECT_CONFIG_VERSION,
    ProjectConfig,
    ProjectConfigError,
    ProjectContext,
    save_project_config,
)
from .runtime_environment import build_profile_environment


class ProjectInitializationError(Exception):
    """Raised when a project initialization operation cannot complete."""


class ProjectBindingsWriteError(ProjectInitializationError):
    """Raised after shared config succeeds but local bindings fail."""

    def __init__(self, config_path: Path, detail: str) -> None:
        self.config_path = config_path
        super().__init__(
            f"project configuration was created at {config_path}, but local "
            f"bindings could not be saved: {detail}"
        )


@dataclass(frozen=True, slots=True)
class InitializationTarget:
    """Resolved destination for a new project configuration."""

    directory: Path
    config_path: Path
    default_project: str


@dataclass(frozen=True, slots=True)
class InitializedEnvironment:
    """One verified environment staged for project initialization."""

    name: str
    profile: str
    account: str
    region: str
    protected: bool
    principal_arn: str | None = None


@dataclass(frozen=True, slots=True)
class InitResult:
    """Successfully persisted project initialization result."""

    project: str
    config_path: Path
    environments: tuple[InitializedEnvironment, ...]


def resolve_initialization_target(start_dir: Path | None = None) -> InitializationTarget:
    """Resolve and validate the directory that will receive ``.awsui.yaml``."""
    requested = Path.cwd() if start_dir is None else Path(start_dir)
    try:
        directory = requested.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ProjectInitializationError(
            f"{requested}: initialization directory does not exist"
        ) from exc
    if not directory.is_dir():
        raise ProjectInitializationError(
            f"{directory}: initialization path is not a directory"
        )

    config_path = directory / PROJECT_CONFIG_FILENAME
    if config_path.exists():
        raise ProjectInitializationError(
            f"{config_path}: project configuration already exists"
        )
    return InitializationTarget(directory, config_path, directory.name)


def verify_initialization_environment(
    *,
    name: str,
    profile: str,
    region: str,
    protected: bool,
    base_environment: Mapping[str, str] | None = None,
    identity_provider: IdentityProvider | None = None,
    login_output: TextIO | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> InitializedEnvironment:
    """Authenticate a selected profile and return a verified staged environment."""
    base = os.environ if base_environment is None else base_environment
    profile_environment = build_profile_environment(
        profile,
        region,
        base_environment=base,
    )
    provider = identity_provider
    if provider is None:

        def provider(selected_profile: str) -> Mapping[str, object] | None:
            return authenticate_profile(
                selected_profile,
                environment=profile_environment,
                login_output=login_output,
                cancel_check=cancel_check,
            )

    identity: AuthenticatedIdentity = authenticate_identity(
        profile,
        identity_provider=provider,
    )
    return InitializedEnvironment(
        name=name,
        profile=profile,
        account=identity.account,
        region=region,
        protected=protected,
        principal_arn=identity.principal_arn,
    )


def commit_project_initialization(
    *,
    project: str,
    environments: Sequence[InitializedEnvironment],
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
) -> InitResult:
    """Persist verified environments to shared config and local bindings."""
    target = resolve_initialization_target(start_dir)
    try:
        bindings = load_bindings(bindings_path)
    except LocalBindingsError as exc:
        raise ProjectInitializationError(str(exc)) from exc

    contexts = {
        item.name: ProjectContext(
            name=item.name,
            account=item.account,
            region=item.region,
            protected=item.protected,
        )
        for item in environments
    }
    config = ProjectConfig(
        version=SUPPORTED_PROJECT_CONFIG_VERSION,
        project=project,
        contexts=contexts,
        source_path=target.config_path,
    )
    try:
        save_project_config(config, overwrite=False)
    except ProjectConfigError as exc:
        raise ProjectInitializationError(str(exc)) from exc

    updated_bindings = bindings
    for item in environments:
        updated_bindings = updated_bindings.with_binding(
            project,
            item.name,
            item.profile,
        )
    try:
        save_bindings(updated_bindings)
    except LocalBindingsError as exc:
        raise ProjectBindingsWriteError(target.config_path, str(exc)) from exc

    return InitResult(
        project=project,
        config_path=target.config_path.resolve(),
        environments=tuple(environments),
    )
