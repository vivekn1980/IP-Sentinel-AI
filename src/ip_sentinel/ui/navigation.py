"""Sidebar Navigation widget for IP Sentinel AI desktop GUI."""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout


class SidebarNavigation(QFrame):
    """Custom sidebar navigation panel with active tab highlighting."""

    view_changed = Signal(str)  # View identifier ("dashboard", "query", "reports", "logs", "settings")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarFrame")
        self.setFixedWidth(220)
        self.buttons = {}
        self.active_view = "dashboard"

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # App Branding Header
        title_label = QLabel("🛡️ IP SENTINEL AI")
        title_label.setObjectName("navTitleLabel")
        subtitle_label = QLabel("WAF Threat Intel & Forensics")
        subtitle_label.setObjectName("navSubtitleLabel")

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)

        # Nav Buttons Definition
        nav_items = [
            ("dashboard", "📊 Dashboard"),
            ("query", "🔍 IP Investigation"),
            ("reports", "📄 Reports Export"),
            ("logs", "📜 Live Audit Logs"),
            ("settings", "⚙️ Settings & Keys"),
        ]

        for view_id, label_text in nav_items:
            btn = QPushButton(label_text)
            btn.setProperty("class", "navButton")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, v=view_id: self.select_view(v))
            self.buttons[view_id] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # Footer Version Notice
        ver_label = QLabel("v1.0.0-foundation\n[Portable Windows EXE]")
        ver_label.setStyleSheet("color: #64748B; font-size: 11px; padding: 12px; font-family: monospace;")
        layout.addWidget(ver_label)

        self.select_view("dashboard")

    def select_view(self, view_id: str):
        """Update active button state and emit navigation signal."""
        if view_id not in self.buttons:
            return

        self.active_view = view_id
        for vid, btn in self.buttons.items():
            is_active = (vid == view_id)
            btn.setChecked(is_active)
            if is_active:
                btn.setProperty("class", "navButton active")
            else:
                btn.setProperty("class", "navButton")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        self.view_changed.emit(view_id)
