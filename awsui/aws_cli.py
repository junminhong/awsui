"""AWS CLI wrapper for STS and SSO operations."""

import json
import subprocess
import time
from typing import Any, Callable, Dict


def check_aws_cli_available() -> bool:
    """Check if AWS CLI v2 is available."""
    try:
        result = subprocess.run(
            ["aws", "--version"], capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and "aws-cli/2" in result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_caller_identity(profile: str) -> Dict[str, Any] | None:
    """
    Execute 'aws sts get-caller-identity' for the given profile.

    Returns parsed JSON response or None on failure.
    """
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--profile", profile],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        return None
    except (subprocess.SubprocessError, json.JSONDecodeError):
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
) -> bool:
    """
    Execute 'aws sso login --profile <name>' with optional cancellation.

    Returns True if login succeeded and False otherwise.
    """
    try:
        process = subprocess.Popen(
            ["aws", "sso", "login", "--profile", profile],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False

    start_time = time.monotonic()

    while True:
        if cancel_check and cancel_check():
            _terminate_process(process)
            return False

        result = process.poll()
        if result is not None:
            return result == 0

        if timeout and (time.monotonic() - start_time) >= timeout:
            _terminate_process(process)
            return False

        time.sleep(poll_interval)


def ensure_authenticated(
    profile: str, cancel_check: Callable[[], bool] | None = None
) -> Dict[str, Any] | None:
    """
    Ensure profile is authenticated, performing SSO login if needed.

    Returns caller identity on success, None on failure.
    """
    if cancel_check and cancel_check():
        return None

    identity = get_caller_identity(profile)
    if identity:
        return identity

    if cancel_check and cancel_check():
        return None

    if sso_login(profile, cancel_check=cancel_check):
        if cancel_check and cancel_check():
            return None
        return get_caller_identity(profile)

    return None
