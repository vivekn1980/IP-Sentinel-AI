"""Dashboard Overview View for IP Sentinel AI desktop GUI."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.signals import SignalBus


class DashboardView(QWidget):
    """Overview metrics screen displaying system status and threat stats."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Header Title
        title_label = QLabel("📊 Security Operations Dashboard")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        layout.addWidget(title_label)

        sub_label = QLabel("WAF Threat Intelligence Overview & Quick Investigation Gateway")
        sub_label.setStyleSheet("color: #94A3B8; font-size: 13px;")
        layout.addWidget(sub_label)

        # Top Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(14)

        card_data = [
            ("TOTAL LOOKUPS", "12", "#00E5FF"),
            ("CLEAN IPS", "8", "#00C853"),
            ("SUSPICIOUS IPS", "2", "#FFB300"),
            ("MALICIOUS IPS", "2", "#FF5252"),
        ]

        for title, count_val, color_hex in card_data:
            card = QFrame()
            card.setProperty("class", "cardFrame")
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(14, 14, 14, 14)

            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: bold;")
            cnt_lbl = QLabel(count_val)
            cnt_lbl.setStyleSheet(f"color: {color_hex}; font-size: 28px; font-weight: bold;")

            c_layout.addWidget(t_lbl)
            c_layout.addWidget(cnt_lbl)
            cards_layout.addWidget(card)

        layout.addLayout(cards_layout)

        # Quick Demo Investigation Panel
        demo_card = QFrame()
        demo_card.setProperty("class", "cardFrame")
        d_layout = QVBoxLayout(demo_card)

        d_title = QLabel("⚡ Quick Investigation Scenarios (Deterministic Mock Engine)")
        d_title.setProperty("class", "cardHeader")
        d_layout.addWidget(d_title)

        d_desc = QLabel("Select a pre-configured IP to test threat intelligence workflows, DNS resolution, and PDF report creation:")
        d_desc.setStyleSheet("color: #94A3B8; margin-bottom: 10px;")
        d_layout.addWidget(d_desc)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        btn_clean = QPushButton("🟢 Test Clean IP (1.1.1.1)")
        btn_clean.setProperty("class", "secondaryButton")
        btn_clean.clicked.connect(lambda: self._trigger_quick_lookup("1.1.1.1"))

        btn_susp = QPushButton("🟡 Test Suspicious IP (198.51.100.45)")
        btn_susp.setProperty("class", "secondaryButton")
        btn_susp.clicked.connect(lambda: self._trigger_quick_lookup("198.51.100.45"))

        btn_mal = QPushButton("🔴 Test Malicious IP (185.220.101.5)")
        btn_mal.setProperty("class", "secondaryButton")
        btn_mal.clicked.connect(lambda: self._trigger_quick_lookup("185.220.101.5"))

        btn_layout.addWidget(btn_clean)
        btn_layout.addWidget(btn_susp)
        btn_layout.addWidget(btn_mal)
        d_layout.addLayout(btn_layout)

        layout.addWidget(demo_card)

        # Architecture & Status Card
        info_card = QFrame()
        info_card.setProperty("class", "cardFrame")
        i_layout = QVBoxLayout(info_card)

        i_title = QLabel("ℹ️ System Architecture & Portable Runtime Status")
        i_title.setProperty("class", "cardHeader")
        i_layout.addWidget(i_title)

        arch_info = (
            "• <b>Portable Windows Runtime</b>: Standalone PySide6 EXE with zero external Python/Node/DB dependencies.<br>"
            "• <b>Background Workers</b>: All network and PDF operations execute asynchronously in QThreadPool.<br>"
            "• <b>Deterministic Mock Engine</b>: Active mock provider handles offline verification & automated tests.<br>"
            "• <b>Zero Hardcoded Secrets</b>: API keys strictly loaded from user configuration or environment variables."
        )
        arch_lbl = QLabel(arch_info)
        arch_lbl.setTextFormat(Qt.TextFormat.RichText)
        arch_lbl.setStyleSheet("color: #E2E8F0; line-height: 140%;")
        i_layout.addWidget(arch_lbl)

        layout.addWidget(info_card)
        layout.addStretch()

    def _trigger_quick_lookup(self, ip: str):
        """Broadcast navigation request to QueryView and auto-fill IP."""
        SignalBus.instance().navigation_requested.emit("query")
        SignalBus.instance().investigation_started.emit(ip)
