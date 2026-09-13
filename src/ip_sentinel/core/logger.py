"""Thread-safe logging framework with rotating file logs and PySide6 QtSignalLogger integration.

Never logs secrets, credentials, or API keys.
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import re
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Signal

from ip_sentinel.core.path_utils import get_app_data_dir

# Regex patterns to sanitize/redact sensitive keys from log strings
SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|password|bearer|auth|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?", re.IGNORECASE),
]


def redact_secrets(message: str) -> str:
    """Sanitize log messages to ensure sensitive tokens are never written to disk or UI."""
    sanitized = message
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(r"\1=***REDACTED***", sanitized)
    return sanitized


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive credentials from record messages."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        return True


class LogSignalEmitter(QObject):
    """Qt QObject wrapper to emit log record signals across thread boundaries."""
    log_emitted = Signal(str, str, str)  # (level_name, formatted_time, message)


class QtSignalLogger(logging.Handler):
    """Custom thread-safe logging handler routing log records to PySide6 UI views."""

    def __init__(self):
        super().__init__()
        self.emitter = LogSignalEmitter()
        self.setFormatter(logging.Formatter("%(message)s"))
        self.addFilter(SensitiveDataFilter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level = record.levelname
            time_str = self.formatter.formatTime(record, "%H:%M:%S") if self.formatter else ""
            self.emitter.log_emitted.emit(level, time_str, msg)
        except Exception:
            self.handleError(record)


_qt_logger_handler: Optional[QtSignalLogger] = None


def setup_logging(log_level_str: str = "INFO") -> QtSignalLogger:
    """Initialize application-wide logging system with console, rotating file, and Qt UI handler.
    
    Returns:
        The singleton QtSignalLogger instance.
    """
    global _qt_logger_handler

    log_dir = get_app_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "ipsentinel.log"

    root_logger = logging.getLogger()
    
    # Map string log level
    numeric_level = getattr(logging, log_level_str.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    root_logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(console_handler)

    # 2. Rotating File Handler (5 MB max, 3 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(file_handler)

    # 3. Qt Signal Handler for UI Log View
    if _qt_logger_handler is None:
        _qt_logger_handler = QtSignalLogger()
    root_logger.addHandler(_qt_logger_handler)

    logging.getLogger("ip_sentinel").info(f"Logging initialized at level {log_level_str}. File: {log_file}")
    return _qt_logger_handler


def get_qt_log_handler() -> Optional[QtSignalLogger]:
    """Retrieve active QtSignalLogger instance."""
    return _qt_logger_handler
