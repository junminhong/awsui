"""AWS CLI wrapper for STS and SSO operations."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
import re
import subprocess
import time
from typing import Any, Callable, Dict, TextIO


_AWS_CLI_VERSION_PATTERN = re.compile(r"aws-cli/(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True, slots=True)
class AwsCliInfo:
    """Parsed AWS CLI installation information."""

    version: tuple[int, int, int]
    raw: str

    @property
    def is_v2(self) -> bool:
        return self.version[0] == 2

    @property
    def supports_console_login(self) -> bool:
        return self.is_v2 and self.version >= (2, 32, 0)


def get_aws_cli_info() -> AwsCliInfo | None:
    """Return parsed AWS CLI version information when available."""
    try:
        result = subprocess.run(
            ["aws", "--version"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    raw = (result.stdout or result.stderr).strip()
    match = _AWS_CLI_VERSION_PATTERN.search(raw)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return AwsCliInfo(version=(major, minor, patch), raw=raw)


def check_aws_cli_available() -> bool:
    """Check if AWS CLI v2 is available."""
    info = get_aws_cli_info()
    return info is not None and info.is_v2


def get_caller_identity(
    profile: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> Dict[str, Any] | None:
    """
    Execute 'aws sts get-caller-identity' for the given profile.

    Returns parsed JSON response or None on failure.
    """
    try:
        run_kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": 10,
        }
        if environment is not None:
            run_kwargs["env"] = dict(environment)
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--profile", profile],
            **run_kwargs,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        return None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    """Terminate process gracefully, falling back to kill if needed."""
    try:
        process.terminate()
    except Exception:
        return

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def sso_login(
    profile: str,
    cancel_check: Callable[[], bool] | None = None,
    timeout: int = 300,
    poll_interval: float = 0.5,
    *,
    environment: Mapping[str, str] | None = None,
    login_output: TextIO | None = None,
) -> bool:
    """
    Execute 'aws sso login --profile <name>' with optional cancellation.

    Returns True if login succeeded and False otherwise.
    """
    return (
        run_aws_interactive(
            ["aws", "sso", "login", "--profile", profile],
            cancel_check=cancel_check,
            timeout=timeout,
            poll_interval=poll_interval,
            environment=environment,
            output=login_output,
        )
        == 0
    )


def console_login(
    profile: str,
    cancel_check: Callable[[], bool] | None = None,
    timeout: int = 300,
    poll_interval: float = 0.5,
    *,
    environment: Mapping[str, str] | None = None,
    login_output: TextIO | None = None,
) -> bool:
    """Authenticate a Console Login profile through the official AWS CLI."""
    return (
        run_aws_interactive(
            ["aws", "login", "--profile", profile],
            cancel_check=cancel_check,
            timeout=timeout,
            poll_interval=poll_interval,
            environment=environment,
            output=login_output,
        )
        == 0
    )


def run_aws_interactive(
    command: list[str],
    *,
    cancel_check: Callable[[], bool] | None = None,
    timeout: int = 0,
    poll_interval: float = 0.5,
    environment: Mapping[str, str] | None = None,
    output: TextIO | None = None,
) -> int:
    """Run an interactive AWS CLI command with cancellation support."""
    try:
        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL if output is None else output,
            "stderr": subprocess.STDOUT,
        }
        if environment is not None:
            popen_kwargs["env"] = dict(environment)
        process = subprocess.Popen(command, **popen_kwargs)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 1

    start_time = time.monotonic()

    try:
        while True:
            if cancel_check and cancel_check():
                _terminate_process(process)
                return 130

            result = process.poll()
            if result is not None:
                return result

            if timeout and (time.monotonic() - start_time) >= timeout:
                _terminate_process(process)
                return 124

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        _terminate_process(process)
        raise
