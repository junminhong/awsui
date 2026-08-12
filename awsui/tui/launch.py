"""Executable discovery and direct-command parsing for the TUI."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import shlex
import shutil


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
