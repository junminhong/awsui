"""Tests for AWS CLI wrapper functions."""

import json
import subprocess
from unittest.mock import Mock, patch


from awsui.aws_cli import (
    check_aws_cli_available,
    get_caller_identity,
    sso_login,
    ensure_authenticated,
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
        with patch("subprocess.Popen") as mock_popen, patch("time.monotonic") as mock_time:
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


class TestEnsureAuthenticated:
    """Tests for ensure_authenticated function."""

    def test_already_authenticated(self):
        """Test when profile is already authenticated."""
        expected_identity = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        }

        with patch("awsui.aws_cli.get_caller_identity") as mock_identity:
            mock_identity.return_value = expected_identity

            identity = ensure_authenticated("test-profile")
            assert identity == expected_identity
            mock_identity.assert_called_once_with("test-profile")

    def test_needs_login_then_succeeds(self):
        """Test authentication requiring SSO login."""
        expected_identity = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        }

        with patch("awsui.aws_cli.get_caller_identity") as mock_identity, patch(
            "awsui.aws_cli.sso_login"
        ) as mock_login:
            # First call returns None (needs login), second returns identity
            mock_identity.side_effect = [None, expected_identity]
            mock_login.return_value = True

            identity = ensure_authenticated("test-profile")
            assert identity == expected_identity
            assert mock_identity.call_count == 2
            mock_login.assert_called_once()

    def test_login_fails(self):
        """Test when SSO login fails."""
        with patch("awsui.aws_cli.get_caller_identity") as mock_identity, patch(
            "awsui.aws_cli.sso_login"
        ) as mock_login:
            mock_identity.return_value = None
            mock_login.return_value = False

            identity = ensure_authenticated("test-profile")
            assert identity is None

    def test_cancelled_before_check(self):
        """Test cancellation before identity check."""
        def cancel_check():
            return True

        identity = ensure_authenticated("test-profile", cancel_check=cancel_check)
        assert identity is None

    def test_cancelled_after_check(self):
        """Test cancellation after initial identity check."""
        cancel_calls = [False, True, False]
        call_index = 0

        def cancel_check():
            nonlocal call_index
            result = cancel_calls[call_index]
            call_index += 1
            return result

        with patch("awsui.aws_cli.get_caller_identity") as mock_identity:
            mock_identity.return_value = None

            identity = ensure_authenticated("test-profile", cancel_check=cancel_check)
            assert identity is None

    def test_cancelled_during_login(self):
        """Test cancellation during SSO login."""
        with patch("awsui.aws_cli.get_caller_identity") as mock_identity, patch(
            "awsui.aws_cli.sso_login"
        ) as mock_login:
            mock_identity.return_value = None
            mock_login.return_value = True

            # Cancel after login succeeds
            cancel_calls = [False, False, True]
            call_index = 0

            def cancel_check():
                nonlocal call_index
                result = cancel_calls[call_index]
                call_index += 1
                return result

            identity = ensure_authenticated("test-profile", cancel_check=cancel_check)
            assert identity is None


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
