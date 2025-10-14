"""Tests for structured logging functionality."""

import json
import logging
from io import StringIO
from unittest.mock import patch


from awsui.logging import StructuredLogger, JSONFormatter, get_logger


class TestStructuredLogger:
    """Tests for StructuredLogger class."""

    def test_logger_initialization(self):
        """Test logger initialization."""
        logger = StructuredLogger(level="INFO")
        assert logger.level == logging.INFO
        assert logger.logger.name == "awsui"

    def test_logger_level_setting(self):
        """Test different log levels."""
        debug_logger = StructuredLogger(level="DEBUG")
        assert debug_logger.level == logging.DEBUG

        warning_logger = StructuredLogger(level="WARNING")
        assert warning_logger.level == logging.WARNING

        error_logger = StructuredLogger(level="ERROR")
        assert error_logger.level == logging.ERROR

    def test_logger_outputs_to_stderr(self):
        """Test that logger outputs to stderr."""
        logger = StructuredLogger(level="INFO")

        # Capture stderr
        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info("test_action", key="value")

        output = captured_stderr.getvalue()
        assert output  # Should have output
        assert "test_action" in output

    def test_info_logging(self):
        """Test info level logging."""
        logger = StructuredLogger(level="INFO")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info("user_login", user="test_user", profile="prod")

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["level"] == "INFO"
        assert log_entry["action"] == "user_login"
        assert log_entry["user"] == "test_user"
        assert log_entry["profile"] == "prod"
        assert "ts" in log_entry

    def test_debug_logging(self):
        """Test debug level logging."""
        logger = StructuredLogger(level="DEBUG")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.debug("debug_action", details="test")

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["level"] == "DEBUG"
        assert log_entry["action"] == "debug_action"

    def test_warning_logging(self):
        """Test warning level logging."""
        logger = StructuredLogger(level="WARNING")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.warning("warning_action", reason="test")

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["level"] == "WARNING"
        assert log_entry["action"] == "warning_action"

    def test_error_logging(self):
        """Test error level logging."""
        logger = StructuredLogger(level="ERROR")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.error("error_action", error="test_error")

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["level"] == "ERROR"
        assert log_entry["action"] == "error_action"
        assert log_entry["error"] == "test_error"

    def test_log_level_filtering(self):
        """Test that log levels are filtered correctly."""
        logger = StructuredLogger(level="WARNING")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.debug("debug_msg")  # Should not appear
            logger.info("info_msg")  # Should not appear
            logger.warning("warning_msg")  # Should appear
            logger.error("error_msg")  # Should appear

        output = captured_stderr.getvalue()

        assert "debug_msg" not in output
        assert "info_msg" not in output
        assert "warning_msg" in output
        assert "error_msg" in output

    def test_timestamp_format(self):
        """Test that timestamp is in ISO format with Z."""
        logger = StructuredLogger(level="INFO")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info("test_action")

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert "ts" in log_entry
        assert log_entry["ts"].endswith("Z")
        # Should be valid ISO format
        from datetime import datetime

        datetime.fromisoformat(log_entry["ts"].replace("Z", "+00:00"))

    def test_additional_fields(self):
        """Test logging with additional custom fields."""
        logger = StructuredLogger(level="INFO")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info(
                "api_call",
                method="GET",
                url="/api/profiles",
                status_code=200,
                duration_ms=150,
            )

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["method"] == "GET"
        assert log_entry["url"] == "/api/profiles"
        assert log_entry["status_code"] == 200
        assert log_entry["duration_ms"] == 150

    def test_nested_data_structures(self):
        """Test logging with nested data structures."""
        logger = StructuredLogger(level="INFO")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info(
                "complex_action",
                metadata={"key1": "value1", "key2": [1, 2, 3]},
                count=5,
            )

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["metadata"] == {"key1": "value1", "key2": [1, 2, 3]}
        assert log_entry["count"] == 5


class TestJSONFormatter:
    """Tests for JSONFormatter class."""

    def test_basic_formatting(self):
        """Test basic JSON formatting."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="test message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        log_entry = json.loads(formatted)

        assert log_entry["level"] == "INFO"
        assert log_entry["action"] == "test message"
        assert "ts" in log_entry

    def test_extra_fields_duration(self):
        """Test formatting with duration_ms field."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="operation",
            args=(),
            exc_info=None,
        )
        record.duration_ms = 250

        formatted = formatter.format(record)
        log_entry = json.loads(formatted)

        assert log_entry["duration_ms"] == 250

    def test_extra_fields_profile(self):
        """Test formatting with profile field."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="profile_operation",
            args=(),
            exc_info=None,
        )
        record.profile = "production"

        formatted = formatter.format(record)
        log_entry = json.loads(formatted)

        assert log_entry["profile"] == "production"

    def test_extra_fields_result(self):
        """Test formatting with result field."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="operation_result",
            args=(),
            exc_info=None,
        )
        record.result = "success"

        formatted = formatter.format(record)
        log_entry = json.loads(formatted)

        assert log_entry["result"] == "success"

    def test_all_extra_fields(self):
        """Test formatting with all extra fields."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="complete_operation",
            args=(),
            exc_info=None,
        )
        record.duration_ms = 300
        record.profile = "staging"
        record.result = "completed"

        formatted = formatter.format(record)
        log_entry = json.loads(formatted)

        assert log_entry["duration_ms"] == 300
        assert log_entry["profile"] == "staging"
        assert log_entry["result"] == "completed"


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_creates_instance(self):
        """Test that get_logger creates a logger instance."""
        # Reset global logger
        import awsui.logging

        awsui.logging._logger = None

        logger = get_logger(level="INFO")
        assert logger is not None
        assert isinstance(logger, StructuredLogger)

    def test_get_logger_returns_singleton(self):
        """Test that get_logger returns the same instance."""
        # Reset global logger
        import awsui.logging

        awsui.logging._logger = None

        logger1 = get_logger(level="INFO")
        logger2 = get_logger(level="DEBUG")

        # Should return the same instance
        assert logger1 is logger2

    def test_get_logger_default_level(self):
        """Test that get_logger uses INFO as default level."""
        # Reset global logger
        import awsui.logging

        awsui.logging._logger = None

        logger = get_logger()
        assert logger.level == logging.INFO


class TestLoggingIntegration:
    """Integration tests for logging functionality."""

    def test_multiple_log_calls(self):
        """Test multiple sequential log calls."""
        logger = StructuredLogger(level="DEBUG")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.debug("step1", status="started")
            logger.info("step2", status="processing")
            logger.warning("step3", status="warning")
            logger.error("step4", status="failed")

        output = captured_stderr.getvalue()
        lines = [line for line in output.strip().split("\n") if line]

        assert len(lines) == 4

        # Parse each line and verify
        log1 = json.loads(lines[0])
        assert log1["action"] == "step1"
        assert log1["level"] == "DEBUG"

        log2 = json.loads(lines[1])
        assert log2["action"] == "step2"
        assert log2["level"] == "INFO"

        log3 = json.loads(lines[2])
        assert log3["action"] == "step3"
        assert log3["level"] == "WARNING"

        log4 = json.loads(lines[3])
        assert log4["action"] == "step4"
        assert log4["level"] == "ERROR"

    def test_logging_performance_metrics(self):
        """Test logging performance-related metrics."""
        logger = StructuredLogger(level="INFO")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.info(
                "api_performance",
                endpoint="/api/profiles",
                method="GET",
                duration_ms=45,
                status_code=200,
                cache_hit=True,
            )

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["action"] == "api_performance"
        assert log_entry["duration_ms"] == 45
        assert log_entry["status_code"] == 200
        assert log_entry["cache_hit"] is True

    def test_logging_error_details(self):
        """Test logging detailed error information."""
        logger = StructuredLogger(level="ERROR")

        captured_stderr = StringIO()
        with patch("sys.stderr", captured_stderr):
            logger.error(
                "authentication_failed",
                profile="test-profile",
                error="InvalidToken",
                error_code="401",
                message="Token has expired",
            )

        output = captured_stderr.getvalue().strip()
        log_entry = json.loads(output)

        assert log_entry["action"] == "authentication_failed"
        assert log_entry["profile"] == "test-profile"
        assert log_entry["error"] == "InvalidToken"
        assert log_entry["error_code"] == "401"
        assert log_entry["message"] == "Token has expired"
