"""Live System Audit & Diagnostic Log Console View screen."""

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.logger import get_qt_log_handler


class LogsView(QWidget):
    """View displaying live streaming application log events."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_logger()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title & Filter Controls
        header_layout = QHBoxLayout()

        title_label = QLabel("📜 Live Audit & System Logs")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")

        self.level_filter = QComboBox()
        self.level_filter.addItems(["ALL", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_filter.setStyleSheet("padding: 4px 10px;")

        btn_clear = QPushButton("🧹 Clear Console")
        btn_clear.setProperty("class", "secondaryButton")
        btn_clear.clicked.connect(self._clear_logs)

        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Filter Level:"))
        header_layout.addWidget(self.level_filter)
        header_layout.addWidget(btn_clear)

        layout.addLayout(header_layout)

        # Log Text Console Widget
        self.log_console = QPlainTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet(
            "background-color: #0B0E14; color: #38BDF8; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;"
        )
        layout.addWidget(self.log_console)

    def _connect_logger(self):
        handler = get_qt_log_handler()
        if handler:
            handler.emitter.log_emitted.connect(self._append_log_line)

    @Slot(str, str, str)
    def _append_log_line(self, level: str, time_str: str, message: str):
        selected_filter = self.level_filter.currentText()
        if selected_filter != "ALL" and level.upper() != selected_filter:
            return

        color_hex = "#38BDF8"  # Default INFO
        if level.upper() in ("WARNING", "WARN"):
            color_hex = "#FBBF24"
        elif level.upper() in ("ERROR", "CRITICAL"):
            color_hex = "#F87171"

        line_html = f"<span style='color: #64748B;'>[{time_str}]</span> <span style='color: {color_hex}; font-weight: bold;'>[{level}]</span> {message}"
        self.log_console.appendHtml(line_html)

    def _clear_logs(self):
        self.log_console.clear()
