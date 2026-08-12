"""Tests for AWS CLI wrapper functions."""

from io import StringIO
import json
import subprocess
from unittest.mock import Mock, patch

import pytest


from awsui.aws_cli import (
    check_aws_cli_available,
    console_login,
    get_aws_cli_info,
    get_caller_identity,
    run_aws_interactive,
    sso_login,
    _terminate_process,
)


class TestCheckAWSCLIAvailable:
    """Tests for check_aws_cli_available function."""

    def test_aws_cli_v2_available(self):
        """Test detecting AWS CLI v2."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="aws-cli/2.13.0 Python/3.11.2 Darwin/23.0.0 source/x86_64",
            )
            assert check_aws_cli_available() is True
            mock_run.assert_called_once()

    def test_aws_cli_v1_not_accepted(self):
        """Test that AWS CLI v1 is not accepted."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="aws-cli/1.32.0 Python/3.9.16",
            )
            assert check_aws_cli_available() is False

    def test_aws_cli_not_found(self):
        """Test when AWS CLI is not installed."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            assert check_aws_cli_available() is False

    def test_aws_cli_command_fails(self):
        """Test when AWS CLI command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            assert check_aws_cli_available() is False

    def test_aws_cli_timeout(self):
        """Test timeout handling."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("aws", 5)
            assert check_aws_cli_available() is False

    def test_console_login_capability_requires_aws_cli_2_32(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="aws-cli/2.32.0 Python/3.13 Darwin/24 source/arm64",
                stderr="",
            )
            info = get_aws_cli_info()

        assert info is not None
        assert info.version == (2, 32, 0)
        assert info.supports_console_login is True

    def test_version_can_be_reported_on_stderr(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="",
                stderr="aws-cli/2.31.9 Python/3.13",
            )
            info = get_aws_cli_info()

        assert info is not None
        assert info.supports_console_login is False


class TestGetCallerIdentity:
    """Tests for get_caller_identity function."""

    def test_successful_identity_fetch(self):
        """Test successful caller identity fetch."""
        expected_identity = {
            "UserId": "AIDACKCEVSQ6C2EXAMPLE",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout=json.dumps(expected_identity)
            )
            identity = get_caller_identity("test-profile")
            assert identity == expected_identity
            mock_run.assert_called_once_with(
                ["aws", "sts", "get-caller-identity", "--profile", "test-profile"],
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_command_failure(self):
        """Test when STS command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            identity = get_caller_identity("test-profile")
            assert identity is None

    def test_invalid_json_response(self):
        """Test handling of invalid JSON response."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="not-valid-json")
            identity = get_caller_identity("test-profile")
            assert identity is None

    def test_subprocess_error(self):
        """Test handling of subprocess errors."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.SubprocessError()
            identity = get_caller_identity("test-profile")
            assert identity is None

    def test_timeout_error(self):
        """Test handling of timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("aws", 10)
            identity = get_caller_identity("test-profile")
            assert identity is None

    def test_aws_cli_not_found(self):
        """Test handling when the AWS CLI executable is unavailable."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            identity = get_caller_identity("test-profile")

        assert identity is None

    def test_explicit_environment_is_passed_to_sts(self):
        environment = {"AWS_PROFILE": "test-profile", "PATH": "/usr/bin"}
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout='{"Account": "123456789012"}',
            )

            identity = get_caller_identity(
                "test-profile",
                environment=environment,
            )

        assert identity == {"Account": "123456789012"}
        assert mock_run.call_args.kwargs["env"] == environment
        assert mock_run.call_args.kwargs["env"] is not environment


class TestSSOLogin:
    """Tests for sso_login function."""

    def test_successful_login(self):
        """Test successful SSO login."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.poll.side_effect = [None, None, 0]  # Running, then success
            mock_popen.return_value = mock_process

            result = sso_login("test-profile", timeout=5)
            assert result is True
            mock_popen.assert_called_once()

    def test_login_failure(self):
        """Test failed SSO login."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = 1  # Failed
            mock_popen.return_value = mock_process

            result = sso_login("test-profile", timeout=5)
            assert result is False

    def test_login_timeout(self):
        """Test SSO login timeout."""
        with (
            patch("subprocess.Popen") as mock_popen,
            patch("time.monotonic") as mock_time,
        ):
            mock_process = Mock()
            mock_process.poll.return_value = None  # Still running
            mock_popen.return_value = mock_process

            # Simulate time progression
            mock_time.side_effect = [0, 0, 301]  # Start, check, timeout

            result = sso_login("test-profile", timeout=300, poll_interval=0.1)
            assert result is False
            mock_process.terminate.assert_called_once()

    def test_login_cancellation(self):
        """Test SSO login cancellation."""
        cancel_flag = False

        def cancel_check():
            return cancel_flag

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None  # Still running
            mock_popen.return_value = mock_process

            # Set cancel flag after first check
            def side_effect():
                nonlocal cancel_flag
                cancel_flag = True
                return None

            mock_process.poll.side_effect = side_effect

            result = sso_login("test-profile", cancel_check=cancel_check, timeout=5)
            assert result is False
            mock_process.terminate.assert_called_once()

    def test_popen_failure(self):
        """Test Popen failure."""
        with patch("subprocess.Popen") as mock_popen:
            mock_popen.side_effect = OSError()
            result = sso_login("test-profile")
            assert result is False

    def test_keyboard_interrupt_terminates_login_process(self):
        """Test Ctrl+C terminates the AWS CLI child before propagating."""
        with (
            patch("subprocess.Popen") as mock_popen,
            patch("time.sleep", side_effect=KeyboardInterrupt),
        ):
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.wait.return_value = None
            mock_popen.return_value = mock_process

            with pytest.raises(KeyboardInterrupt):
                sso_login("test-profile", timeout=5)

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once_with(timeout=5)

    def test_explicit_environment_and_output_are_passed_to_login(self):
        environment = {"AWS_PROFILE": "test-profile"}
        output = StringIO()
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            result = sso_login(
                "test-profile",
                environment=environment,
                login_output=output,
            )

        assert result is True
        assert mock_popen.call_args.kwargs["env"] == environment
        assert mock_popen.call_args.kwargs["env"] is not environment
        assert mock_popen.call_args.kwargs["stdout"] is output


class TestConsoleLogin:
    def test_uses_console_login_command(self):
        with patch("awsui.aws_cli.run_aws_interactive", return_value=0) as runner:
            assert console_login("console-dev") is True

        runner.assert_called_once_with(
            ["aws", "login", "--profile", "console-dev"],
            cancel_check=None,
            timeout=300,
            poll_interval=0.5,
            environment=None,
            output=None,
        )

    def test_interactive_runner_returns_child_exit_code(self):
        with patch("subprocess.Popen") as mock_popen:
            process = Mock()
            process.poll.return_value = 7
            mock_popen.return_value = process

            assert run_aws_interactive(["aws", "configure"]) == 7


class TestTerminateProcess:
    """Tests for _terminate_process function."""

    def test_graceful_termination(self):
        """Test graceful process termination."""
        mock_process = Mock()
        mock_process.wait.return_value = None

        _terminate_process(mock_process)

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called()

    def test_terminate_failure_then_kill(self):
        """Test falling back to kill after terminate timeout."""
        mock_process = Mock()
        mock_process.wait.side_effect = [subprocess.TimeoutExpired("cmd", 5), None]

        _terminate_process(mock_process)

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
        assert mock_process.wait.call_count == 2

    def test_terminate_exception_ignored(self):
        """Test that terminate exceptions are ignored."""
        mock_process = Mock()
        mock_process.terminate.side_effect = Exception("test error")

        # Should not raise
        _terminate_process(mock_process)

    def test_kill_timeout_ignored(self):
        """Test that kill timeout is ignored."""
        mock_process = Mock()
        mock_process.wait.side_effect = [
            subprocess.TimeoutExpired("cmd", 5),
            subprocess.TimeoutExpired("cmd", 5),
        ]

        # Should not raise
        _terminate_process(mock_process)

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
