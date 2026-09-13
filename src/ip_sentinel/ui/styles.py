"""Theme loader utility applying QSS stylesheets."""

import logging
from PySide6.QtWidgets import QApplication

from ip_sentinel.core.path_utils import get_resource_path

logger = logging.getLogger("ip_sentinel.ui.styles")


def apply_dark_theme(app: QApplication) -> None:
    """Load and set dark cybersecurity QSS stylesheet on QApplication instance."""
    qss_path = get_resource_path("styles/dark_theme.qss")
    if qss_path.exists():
        try:
            with open(qss_path, "r", encoding="utf-8") as f:
                stylesheet = f.read()
            app.setStyleSheet(stylesheet)
            logger.info("Successfully applied dark cybersecurity QSS theme.")
        except Exception as err:
            logger.error(f"Failed to read QSS stylesheet from {qss_path}: {err}")
    else:
        logger.warning(f"QSS stylesheet missing at {qss_path}. Using fallback Qt defaults.")
