"""Tests for Amazon Q Developer CLI integration."""

import subprocess
from unittest.mock import Mock, patch


from awsui.q_assistant import (
    check_q_cli_available,
    get_q_cli_version,
    query_q_cli,
    stream_q_cli_query,
    clean_ansi_codes,
    format_aws_context,
)


class TestCheckQCLIAvailable:
    """Tests for check_q_cli_available function."""

    def test_q_cli_available(self):
        """Test when Q CLI is available."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/local/bin/q"
            assert check_q_cli_available() is True
            mock_which.assert_called_once_with("q")

    def test_q_cli_not_available(self):
        """Test when Q CLI is not available."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None
            assert check_q_cli_available() is False


class TestGetQCLIVersion:
    """Tests for get_q_cli_version function."""

    def test_successful_version_fetch(self):
        """Test successful version fetch."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="q version 1.2.3\n")
            version = get_q_cli_version()
            assert version == "q version 1.2.3"

    def test_version_command_fails(self):
        """Test when version command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            version = get_q_cli_version()
            assert version is None

    def test_q_cli_not_found(self):
        """Test when Q CLI is not found."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            version = get_q_cli_version()
            assert version is None

    def test_subprocess_error(self):
        """Test handling of subprocess errors."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.SubprocessError()
            version = get_q_cli_version()
            assert version is None


class TestQueryQCLI:
    """Tests for query_q_cli function."""

    def test_successful_query(self):
        """Test successful query execution."""
        expected_response = "Here is how to list S3 buckets:\naws s3 ls"

        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_process.communicate.return_value = (expected_response, "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            response, success = query_q_cli("How to list S3 buckets?")

            assert success is True
            assert expected_response in response
            mock_popen.assert_called_once()

    def test_query_with_context(self):
        """Test query with AWS context."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_process.communicate.return_value = ("Response", "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            context = "Current profile: prod, Region: us-east-1"
            response, success = query_q_cli("List buckets", context=context)

            assert success is True
            # Check that context was included in the prompt
            call_args = mock_popen.call_args
            assert context in call_args[0][0][-1]

    def test_query_with_profile_and_region(self):
        """Test query with profile and region environment variables."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_process.communicate.return_value = ("Response", "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            response, success = query_q_cli(
                "Test query", profile_name="test-profile", region="us-west-2"
            )

            assert success is True
            # Check environment variables were set
            call_kwargs = mock_popen.call_args[1]
            assert call_kwargs["env"]["AWS_PROFILE"] == "test-profile"
            assert call_kwargs["env"]["AWS_DEFAULT_REGION"] == "us-west-2"

    def test_query_failure(self):
        """Test query failure."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_process.communicate.return_value = ("", "Error message")
            mock_process.returncode = 1
            mock_popen.return_value = mock_process

            response, success = query_q_cli("Test query")

            assert success is False
            assert "Error" in response

    def test_query_timeout(self):
        """Test query timeout."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_process.communicate.side_effect = subprocess.TimeoutExpired("q", 300)
            mock_popen.return_value = mock_process

            response, success = query_q_cli("Test query", timeout=5)

            assert success is False
            assert "timed out" in response.lower()
            mock_process.kill.assert_called_once()

    def test_query_cancellation(self):
        """Test query cancellation."""
        def cancel_check():
            return True

        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_popen.return_value = mock_process

            response, success = query_q_cli("Test query", cancel_check=cancel_check)

            assert success is False
            assert "cancelled" in response.lower()
            mock_process.terminate.assert_called_once()

    def test_q_cli_not_available(self):
        """Test when Q CLI is not available."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check:
            mock_check.return_value = False

            response, success = query_q_cli("Test query")

            assert success is False
            assert "not available" in response.lower()

    def test_q_cli_not_found_exception(self):
        """Test FileNotFoundError handling."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_popen.side_effect = FileNotFoundError()

            response, success = query_q_cli("Test query")

            assert success is False
            assert "not found" in response.lower()


class TestStreamQCLIQuery:
    """Tests for stream_q_cli_query function."""

    def test_successful_stream(self):
        """Test successful streaming query."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_popen.return_value = mock_process

            process = stream_q_cli_query("Test query")

            assert process == mock_process
            mock_popen.assert_called_once()

    def test_stream_with_context(self):
        """Test streaming with context."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_popen.return_value = mock_process

            context = "Profile: test"
            process = stream_q_cli_query("Query", context=context)

            assert process == mock_process
            # Verify context was included
            call_args = mock_popen.call_args[0][0]
            assert context in call_args[-1]

    def test_stream_with_profile_and_region(self):
        """Test streaming with profile and region."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_process = Mock()
            mock_popen.return_value = mock_process

            process = stream_q_cli_query(
                "Query", profile_name="prod", region="eu-west-1"
            )

            assert process == mock_process
            env = mock_popen.call_args[1]["env"]
            assert env["AWS_PROFILE"] == "prod"
            assert env["AWS_DEFAULT_REGION"] == "eu-west-1"

    def test_stream_cancellation(self):
        """Test stream cancellation."""
        def cancel_check():
            return True

        with patch("awsui.q_assistant.check_q_cli_available") as mock_check:
            mock_check.return_value = True

            process = stream_q_cli_query("Query", cancel_check=cancel_check)

            assert process is None

    def test_stream_q_cli_not_available(self):
        """Test streaming when Q CLI is not available."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check:
            mock_check.return_value = False

            process = stream_q_cli_query("Query")

            assert process is None

    def test_stream_subprocess_error(self):
        """Test handling subprocess errors."""
        with patch("awsui.q_assistant.check_q_cli_available") as mock_check, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_check.return_value = True
            mock_popen.side_effect = subprocess.SubprocessError()

            process = stream_q_cli_query("Query")

            assert process is None


class TestCleanANSICodes:
    """Tests for clean_ansi_codes function."""

    def test_clean_simple_ansi_codes(self):
        """Test cleaning simple ANSI codes."""
        text = "\x1b[31mRed text\x1b[0m"
        cleaned = clean_ansi_codes(text)
        assert cleaned == "Red text"

    def test_clean_complex_ansi_codes(self):
        """Test cleaning complex ANSI codes."""
        text = "\x1b[1;32;40mBold green on black\x1b[0m"
        cleaned = clean_ansi_codes(text)
        assert cleaned == "Bold green on black"

    def test_clean_cursor_movement_codes(self):
        """Test cleaning cursor movement codes."""
        text = "\x1b[2JClear screen\x1b[H"
        cleaned = clean_ansi_codes(text)
        assert "Clear screen" in cleaned
        assert "\x1b" not in cleaned

    def test_no_ansi_codes(self):
        """Test text without ANSI codes."""
        text = "Plain text"
        cleaned = clean_ansi_codes(text)
        assert cleaned == text

    def test_empty_string(self):
        """Test empty string."""
        cleaned = clean_ansi_codes("")
        assert cleaned == ""

    def test_multiple_ansi_sequences(self):
        """Test multiple ANSI sequences."""
        text = "\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m"
        cleaned = clean_ansi_codes(text)
        assert cleaned == "Red Green Blue"
        assert "\x1b" not in cleaned


class TestFormatAWSContext:
    """Tests for format_aws_context function."""

    def test_format_with_all_fields(self):
        """Test formatting with all context fields."""
        context = format_aws_context(
            profile_name="prod", region="us-east-1", account="123456789012"
        )

        assert "prod" in context
        assert "us-east-1" in context
        assert "123456789012" in context
        assert "Context:" in context

    def test_format_with_profile_only(self):
        """Test formatting with profile only."""
        context = format_aws_context(profile_name="dev")

        assert "dev" in context
        assert "Context:" in context

    def test_format_with_region_only(self):
        """Test formatting with region only."""
        context = format_aws_context(region="eu-west-1")

        assert "eu-west-1" in context
        assert "Region:" in context

    def test_format_with_account_only(self):
        """Test formatting with account only."""
        context = format_aws_context(account="999888777666")

        assert "999888777666" in context
        assert "Account" in context

    def test_format_with_no_fields(self):
        """Test formatting with no fields."""
        context = format_aws_context()

        assert context == ""

    def test_format_with_none_values(self):
        """Test formatting with None values."""
        context = format_aws_context(profile_name=None, region=None, account=None)

        assert context == ""

    def test_format_profile_and_region(self):
        """Test formatting with profile and region."""
        context = format_aws_context(profile_name="staging", region="ap-southeast-1")

        assert "staging" in context
        assert "ap-southeast-1" in context
        assert context.count(",") == 1  # One separator between two items
