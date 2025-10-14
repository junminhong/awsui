"""Amazon Q Developer CLI integration for AI-powered assistance."""

import os
import re
import shutil
import subprocess
from typing import Callable


def check_q_cli_available() -> bool:
    """
    Check if Amazon Q Developer CLI is available.

    Returns True if 'q' command is found in PATH, False otherwise.
    """
    return shutil.which("q") is not None


def get_q_cli_version() -> str | None:
    """
    Get Amazon Q Developer CLI version.

    Returns version string or None if unable to determine.
    """
    try:
        result = subprocess.run(
            ["q", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def query_q_cli(
    prompt: str,
    context: str | None = None,
    profile_name: str | None = None,
    region: str | None = None,
    cancel_check: Callable[[], bool] | None = None,
    timeout: int = 300,
) -> tuple[str, bool]:
    """
    Query Amazon Q Developer CLI with a prompt.

    Args:
        prompt: User's question or command to ask Q
        context: Optional context information (profile, region, etc.)
        profile_name: AWS profile name to use
        region: AWS region to use
        cancel_check: Optional callable that returns True if operation should be cancelled
        timeout: Timeout in seconds (default: 300)

    Returns:
        Tuple of (response_text, success)
        - response_text: Q's response or error message
        - success: True if query succeeded, False otherwise
    """
    if not check_q_cli_available():
        return ("Amazon Q Developer CLI not available. Please install it first.", False)

    full_prompt = prompt
    if context:
        full_prompt = f"{context}\n\n{prompt}"

    env = os.environ.copy()
    if profile_name:
        env["AWS_PROFILE"] = profile_name
    if region:
        env["AWS_DEFAULT_REGION"] = region

    try:
        # Note: --trust-all-tools allows Q to use tools without confirmation
        process = subprocess.Popen(
            [
                "q",
                "chat",
                "--no-interactive",
                "--trust-all-tools",
                "--wrap",
                "never",
                full_prompt,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        if cancel_check and cancel_check():
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
            return ("Query cancelled.", False)

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return ("Query timed out after {timeout} seconds.", False)

        if process.returncode == 0:
            clean_output = clean_ansi_codes(stdout.strip())
            return (clean_output, True)
        else:
            error_msg = stderr.strip() if stderr else "Unknown error occurred"
            clean_error = clean_ansi_codes(error_msg)
            return (f"Error: {clean_error}", False)

    except FileNotFoundError:
        return ("Amazon Q Developer CLI 'q' command not found.", False)
    except Exception as e:
        return (f"Unexpected error: {str(e)}", False)


def stream_q_cli_query(
    prompt: str,
    context: str | None = None,
    profile_name: str | None = None,
    region: str | None = None,
    cancel_check: Callable[[], bool] | None = None,
    timeout: int = 300,
) -> subprocess.Popen[str] | None:
    """
    Start a streaming query to Amazon Q Developer CLI.

    Args:
        prompt: User's question or command to ask Q
        context: Optional context information (profile, region, etc.)
        profile_name: AWS profile name to use
        region: AWS region to use
        cancel_check: Optional callable that returns True if operation should be cancelled
        timeout: Timeout in seconds (default: 300)

    Returns:
        subprocess.Popen object with stdout available for streaming, or None on failure
        Caller is responsible for handling the process and reading from stdout
    """
    if not check_q_cli_available():
        return None

    if cancel_check and cancel_check():
        return None

    full_prompt = prompt
    if context:
        full_prompt = f"{context}\n\n{prompt}"

    env = os.environ.copy()
    if profile_name:
        env["AWS_PROFILE"] = profile_name
    if region:
        env["AWS_DEFAULT_REGION"] = region

    try:
        # Note: --trust-all-tools allows Q to use tools without confirmation
        process = subprocess.Popen(
            [
                "q",
                "chat",
                "--no-interactive",
                "--trust-all-tools",
                "--wrap",
                "never",
                full_prompt,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            env=env,
        )
        return process
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


def clean_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Args:
        text: Text potentially containing ANSI codes

    Returns:
        Clean text without ANSI codes
    """
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def format_aws_context(
    profile_name: str | None = None,
    region: str | None = None,
    account: str | None = None,
) -> str:
    """
    Format AWS context information for Q CLI query.

    Args:
        profile_name: Current AWS profile name
        region: Current AWS region
        account: Current AWS account ID

    Returns:
        Formatted context string
    """
    context_parts = []

    if profile_name:
        context_parts.append(f"Current AWS Profile: {profile_name}")
    if region:
        context_parts.append(f"Region: {region}")
    if account:
        context_parts.append(f"Account ID: {account}")

    if context_parts:
        return "Context: " + ", ".join(context_parts)
    return ""
