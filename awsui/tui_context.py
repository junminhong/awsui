"""Pure state loading for the project-aware Textual dashboard."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import shlex
import shutil

from .bindings import load_bindings
from .models import Profile
from .profile_catalog import load_profile_catalog
from .project_config import find_project_config, load_project_config


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


@dataclass(frozen=True, slots=True)
class DetectedTool:
    """A known executable available on the current PATH."""

    label: str
    executable: str
    path: str


class LaunchCommandError(ValueError):
    """Raised when a custom launch command is empty or requires a shell."""


_KNOWN_TOOLS: tuple[tuple[str, str], ...] = (
    ("Claude Code", "claude"),
    ("Codex", "codex"),
    ("Kiro CLI", "kiro-cli"),
    ("Terraform", "terraform"),
    ("AWS CLI", "aws"),
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


def detect_tools(
    environment: Mapping[str, str],
    *,
    resolver: Callable[[str, str | None], str | None] | None = None,
) -> tuple[DetectedTool, ...]:
    """Detect supported convenience launchers without integrating providers."""
    selected_resolver = _resolve_executable if resolver is None else resolver
    path = environment.get("PATH")
    detected: list[DetectedTool] = []
    for label, executable in _KNOWN_TOOLS:
        resolved_path = selected_resolver(executable, path)
        if resolved_path is not None:
            detected.append(DetectedTool(label, executable, resolved_path))
    return tuple(detected)


def parse_launch_command(command: str) -> tuple[str, ...]:
    """Parse one direct argv command, explicitly rejecting shell syntax."""
    try:
        argv = tuple(shlex.split(command, posix=True))
    except ValueError as exc:
        raise LaunchCommandError(str(exc)) from exc
    if not argv:
        raise LaunchCommandError("enter a command to launch")

    shell_operators = {"|", "||", "&&", ";", ">", ">>", "<", "<<", "&"}
    unsupported = next((token for token in argv if token in shell_operators), None)
    if unsupported is not None:
        raise LaunchCommandError(
            f"shell operator {unsupported!r} is not supported; open a verified shell"
        )
    return argv


def _resolve_executable(executable: str, path: str | None) -> str | None:
    return shutil.which(executable, path=path)
