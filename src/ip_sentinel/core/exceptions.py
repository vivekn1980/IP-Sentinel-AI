"""Custom exception hierarchy and Qt-aware global exception handling framework.
"""

import logging
import sys
import traceback
from typing import Optional, Type


logger = logging.getLogger("ip_sentinel.exceptions")


class IPSentinelError(Exception):
    """Base exception class for all IP Sentinel AI application errors."""
    def __init__(self, message: str, user_message: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.user_message = user_message or message


class ConfigError(IPSentinelError):
    """Raised when configuration loading, parsing, or validation fails."""
    pass


class ProviderError(IPSentinelError):
    """Raised when a threat intelligence provider encounters an operational error."""
    pass


class ReportError(IPSentinelError):
    """Raised when report generation (HTML/PDF) fails."""
    pass


class NetworkError(IPSentinelError):
    """Raised when DNS or HTTP network resolution fails."""
    pass


class ValidationError(IPSentinelError):
    """Raised when input validation (e.g. malformed IP address) fails."""
    pass


def global_exception_hook(exctype: Type[BaseException], value: BaseException, tb) -> None:
    """Qt-aware global exception hook replacing sys.excepthook.
    
    Prevents silent application crashes, logs full tracebacks to log files,
    and shows user-friendly non-technical error notifications.
    """
    if issubclass(exctype, KeyboardInterrupt):
        sys.__excepthook__(exctype, value, tb)
        return

    tb_text = "".join(traceback.format_exception(exctype, value, tb))
    logger.critical(f"Unhandled Exception: {exctype.__name__}: {value}\n{tb_text}")

    # Emit signal or show dialog if PySide6 application loop is running
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance()
        if app and app.thread() == app.thread().currentThread():
            user_msg = getattr(value, "user_message", str(value))
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Icon.Critical)
            msg_box.setWindowTitle("IP Sentinel AI - Unexpected Error")
            msg_box.setText("An unexpected application error occurred.")
            msg_box.setInformativeText(user_msg)
            msg_box.setDetailedText(tb_text)
            msg_box.exec()
    except Exception as hook_err:
        logger.error(f"Failed to display Qt error dialog: {hook_err}")


def setup_global_exception_handler() -> None:
    """Attach custom exception hook to sys.excepthook."""
    sys.excepthook = global_exception_hook
