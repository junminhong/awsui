"""Structured logging utility for awsui."""

import sys
import json
import logging
from datetime import datetime


class StructuredLogger:
    """JSON structured logger that outputs to STDERR."""

    def __init__(self, level: str = "INFO"):
        self.level = getattr(logging, level.upper())
        self.logger = logging.getLogger("awsui")
        self.logger.setLevel(self.level)

        # Remove any existing handlers
        self.logger.handlers.clear()

        # Add stderr handler with JSON formatter
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JSONFormatter())
        self.logger.addHandler(handler)

    def _log(self, level: str, action: str, **kwargs):
        """Internal log method."""
        record = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "action": action,
        }
        record.update(kwargs)

        # Output to stderr as JSON
        json.dump(record, sys.stderr)
        sys.stderr.write("\n")
        sys.stderr.flush()

    def debug(self, action: str, **kwargs):
        """Log debug message."""
        if self.level <= logging.DEBUG:
            self._log("DEBUG", action, **kwargs)

    def info(self, action: str, **kwargs):
        """Log info message."""
        if self.level <= logging.INFO:
            self._log("INFO", action, **kwargs)

    def warning(self, action: str, **kwargs):
        """Log warning message."""
        if self.level <= logging.WARNING:
            self._log("WARNING", action, **kwargs)

    def error(self, action: str, **kwargs):
        """Log error message."""
        if self.level <= logging.ERROR:
            self._log("ERROR", action, **kwargs)


class JSONFormatter(logging.Formatter):
    """JSON formatter for standard logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "action": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
        if hasattr(record, "profile"):
            log_data["profile"] = record.profile
        if hasattr(record, "result"):
            log_data["result"] = record.result

        return json.dumps(log_data)


# Global logger instance
_logger: StructuredLogger | None = None


def get_logger(level: str = "INFO") -> StructuredLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = StructuredLogger(level)
    return _logger
