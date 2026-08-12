"""Pure state loading for the project-aware Textual dashboard."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..profiles.catalog import load_profile_catalog
from ..profiles.models import Profile
from ..project.bindings import load_bindings
from ..project.config import find_project_config, load_project_config


class ContextStatus(Enum):
    """Local readiness state before optional STS verification."""

    UNBOUND = "unbound"
    PROFILE_MISSING = "profile-missing"
    READY = "ready"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One project environment and its local binding readiness."""

    name: str
    expected_account: str
    region: str
    protected: bool
    profile: str | None
    status: ContextStatus


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    """Locally resolved dashboard data with no AWS network calls."""

    project: str
    config_path: Path
    bindings_path: Path
    contexts: tuple[ContextItem, ...]

    def get(self, environment: str) -> ContextItem | None:
        """Return one environment by its configured name."""
        return next(
            (context for context in self.contexts if context.name == environment),
            None,
        )


def load_dashboard(
    *,
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
    profiles_loader: Callable[[], Sequence[Profile]] | None = None,
) -> DashboardSnapshot:
    """Load project contexts, bindings, and local profile availability."""
    config_path = find_project_config(start_dir)
    project = load_project_config(config_path)
    bindings = load_bindings(bindings_path)
    catalog = load_profile_catalog(
        None if profiles_loader is None else lambda: list(profiles_loader())
    )

    contexts: list[ContextItem] = []
    for context in project.contexts.values():
        profile = bindings.get_profile(project.project, context.name)
        if profile is None:
            status = ContextStatus.UNBOUND
        elif catalog.get(profile) is None:
            status = ContextStatus.PROFILE_MISSING
        else:
            status = ContextStatus.READY
        contexts.append(
            ContextItem(
                name=context.name,
                expected_account=context.account,
                region=context.region,
                protected=context.protected,
                profile=profile,
                status=status,
            )
        )

    return DashboardSnapshot(
        project=project.project,
        config_path=project.source_path,
        bindings_path=bindings.source_path,
        contexts=tuple(contexts),
    )
