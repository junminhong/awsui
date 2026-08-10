"""Foreground execution for verified AWS context commands."""

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
import os
import signal
import subprocess
import threading
from typing import Iterator


class CommandLaunchError(Exception):
    """Raised when a child command cannot be launched."""

    exit_code = 1

    def __init__(self, executable: str, detail: str) -> None:
        self.executable = executable
        self.detail = detail
        super().__init__(detail)


class CommandNotFoundError(CommandLaunchError):
    """Raised when the requested executable cannot be found."""

    exit_code = 127


class CommandPermissionError(CommandLaunchError):
    """Raised when the requested executable cannot be executed."""

    exit_code = 126


def run_command(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
) -> int:
    """Run argv in the foreground with inherited terminal streams."""
    argv = list(command)
    if not argv:
        raise ValueError("command must not be empty")

    try:
        process = subprocess.Popen(argv, env=dict(environment))
    except FileNotFoundError as exc:
        raise CommandNotFoundError(
            argv[0],
            f"command not found: {argv[0]}",
        ) from exc
    except PermissionError as exc:
        raise CommandPermissionError(
            argv[0],
            f"permission denied: {argv[0]}",
        ) from exc
    except OSError as exc:
        raise CommandLaunchError(
            argv[0],
            f"unable to launch {argv[0]!r}: {exc}",
        ) from exc

    try:
        with _ignore_parent_terminal_signals():
            return_code = process.wait()
    except KeyboardInterrupt:
        return _finish_interrupted_process(process)

    if return_code < 0:
        return 128 + abs(return_code)
    return return_code


def select_interactive_shell(
    environment: Mapping[str, str],
    *,
    platform: str = os.name,
) -> str:
    """Select the user's interactive shell with platform fallbacks."""
    if platform == "nt":
        return environment.get("COMSPEC") or "cmd.exe"
    return environment.get("SHELL") or "/bin/sh"


@contextmanager
def _ignore_parent_terminal_signals() -> Iterator[None]:
    if os.name != "posix" or threading.current_thread() is not threading.main_thread():
        yield
        return

    previous_handlers: dict[signal.Signals, signal.Handlers] = {}
    for signal_number in (signal.SIGINT, signal.SIGQUIT):
        previous_handlers[signal_number] = signal.getsignal(signal_number)
        signal.signal(signal_number, signal.SIG_IGN)

    try:
        yield
    finally:
        for signal_number, handler in previous_handlers.items():
            signal.signal(signal_number, handler)


def _finish_interrupted_process(process: subprocess.Popen[bytes]) -> int:
    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 130

    if return_code < 0:
        return 128 + abs(return_code)
    return return_code or 130
