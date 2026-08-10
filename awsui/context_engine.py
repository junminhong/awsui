"""Deterministic project context resolution."""

from dataclasses import dataclass
from pathlib import Path

from .bindings import LocalBindingsError, load_bindings
from .project_config import (
    ProjectConfigError,
    find_project_config,
    load_project_config,
)


@dataclass(frozen=True, slots=True)
class ResolvedContext:
    """A locally resolved AWS context that has not been identity-verified."""

    project: str
    environment: str
    expected_account: str
    region: str
    profile: str
    protected: bool
    project_config_path: Path
    bindings_path: Path


class ContextResolutionError(Exception):
    """Base error for deterministic context resolution."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class ContextSourceError(ContextResolutionError):
    """Raised when a project config or bindings source cannot be loaded."""

    def __init__(self, source: str, path: Path, detail: str) -> None:
        self.source = source
        self.path = path
        super().__init__(f"{source} error at {path}: {detail}")


class EnvironmentNotFoundError(ContextResolutionError):
    """Raised when a requested project environment does not exist."""

    def __init__(
        self,
        project: str,
        environment: str,
        available_environments: tuple[str, ...],
    ) -> None:
        self.project = project
        self.environment = environment
        self.available_environments = available_environments
        available = ", ".join(available_environments)
        super().__init__(
            f"unknown environment {environment!r} for project {project!r}; "
            f"available environments: {available}"
        )


class BindingNotFoundError(ContextResolutionError):
    """Raised when a project environment has no local profile binding."""

    def __init__(self, project: str, environment: str) -> None:
        self.project = project
        self.environment = environment
        super().__init__(
            f"no local profile binding for {project}/{environment}; "
            f"run 'awsui bind {environment}'"
        )


def resolve_context(
    environment: str,
    *,
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
) -> ResolvedContext:
    """Resolve project configuration and local profile binding without AWS I/O."""
    try:
        project_config_path = find_project_config(start_dir)
        project_config = load_project_config(project_config_path)
    except ProjectConfigError as exc:
        raise ContextSourceError(
            "project configuration",
            exc.path,
            exc.detail,
        ) from exc

    project_context = project_config.contexts.get(environment)
    if project_context is None:
        raise EnvironmentNotFoundError(
            project=project_config.project,
            environment=environment,
            available_environments=tuple(sorted(project_config.contexts)),
        )

    try:
        bindings = load_bindings(bindings_path)
    except LocalBindingsError as exc:
        raise ContextSourceError(
            "local bindings",
            exc.path,
            exc.detail,
        ) from exc

    profile = bindings.get_profile(project_config.project, environment)
    if profile is None:
        raise BindingNotFoundError(
            project=project_config.project,
            environment=environment,
        )

    return ResolvedContext(
        project=project_config.project,
        environment=environment,
        expected_account=project_context.account,
        region=project_context.region,
        profile=profile,
        protected=project_context.protected,
        project_config_path=project_config.source_path,
        bindings_path=bindings.source_path,
    )
