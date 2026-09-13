"""Settings & Provider API Credentials Manager View screen."""

import logging
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.config import ConfigManager

logger = logging.getLogger("ip_sentinel.ui.views.settings")


class SettingsView(QWidget):
    """View interface for managing application settings and API provider keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_mgr = ConfigManager()
        self.key_inputs = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header Title
        title_label = QLabel("⚙️ Settings & Threat Intelligence Providers")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        layout.addWidget(title_label)

        # Provider Key Manager Card
        key_card = QFrame()
        key_card.setProperty("class", "cardFrame")
        k_layout = QVBoxLayout(key_card)

        k_title = QLabel("Threat Intelligence Provider Credentials")
        k_title.setProperty("class", "cardHeader")
        k_layout.addWidget(k_title)

        k_desc = QLabel("API keys are saved in local credential storage. Never hardcoded or transmitted off-device:")
        k_desc.setStyleSheet("color: #94A3B8; margin-bottom: 10px;")
        k_layout.addWidget(k_desc)

        grid = QGridLayout()
        grid.setSpacing(10)

        providers = [
            ("mock", "Mock Engine (Deterministic)", "ACTIVE (No Key Required)", False),
            ("abuseipdb", "AbuseIPDB API v2", "Deferred / Unconfigured", True),
            ("virustotal", "VirusTotal v3 API", "Deferred / Unconfigured", True),
            ("shodan", "Shodan Host API", "Deferred / Unconfigured", True),
            ("otx", "AlienVault OTX API", "Deferred / Unconfigured", True),
        ]

        for idx, (p_id, p_name, p_status, requires_key) in enumerate(providers):
            lbl_name = QLabel(f"<b>{p_name}</b>")
            lbl_status = QLabel(f"[{p_status}]")
            lbl_status.setStyleSheet("color: #34D399;" if "ACTIVE" in p_status else "color: #94A3B8;")

            grid.addWidget(lbl_name, idx, 0)
            grid.addWidget(lbl_status, idx, 1)

            if requires_key:
                inp = QLineEdit()
                inp.setEchoMode(QLineEdit.EchoMode.Password)
                inp.setPlaceholderText(f"Enter {p_name} API Key...")
                existing_key = self.config_mgr.secret_store.get_secret(p_id)
                if existing_key:
                    inp.setText(existing_key)
                self.key_inputs[p_id] = inp
                grid.addWidget(inp, idx, 2)
            else:
                lbl_na = QLabel("N/A")
                lbl_na.setStyleSheet("color: #64748B;")
                grid.addWidget(lbl_na, idx, 2)

        k_layout.addLayout(grid)

        # Save Button Row
        btn_save_keys = QPushButton("💾 Save Credentials")
        btn_save_keys.setProperty("class", "primaryButton")
        btn_save_keys.clicked.connect(self._save_credentials)
        k_layout.addWidget(btn_save_keys)

        layout.addWidget(key_card)

        # General App Settings Card
        gen_card = QFrame()
        gen_card.setProperty("class", "cardFrame")
        g_layout = QVBoxLayout(gen_card)

        g_title = QLabel("General Preferences")
        g_title.setProperty("class", "cardHeader")
        g_layout.addWidget(g_title)

        btn_reset = QPushButton("⚠️ Reset All Settings to Defaults")
        btn_reset.setProperty("class", "secondaryButton")
        btn_reset.clicked.connect(self._reset_defaults)
        g_layout.addWidget(btn_reset)

        layout.addWidget(gen_card)
        layout.addStretch()

    def _save_credentials(self):
        saved_count = 0
        for p_id, inp in self.key_inputs.items():
            val = inp.text().strip()
            if val:
                self.config_mgr.secret_store.set_secret(p_id, val)
                saved_count += 1
            else:
                self.config_mgr.secret_store.delete_secret(p_id)

        QMessageBox.information(
            self,
            "Settings Saved",
            f"Successfully updated credential store ({saved_count} API keys configured).",
        )

    def _reset_defaults(self):
        reply = QMessageBox.question(
            self,
            "Reset Confirmation",
            "Are you sure you want to reset all settings back to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.config_mgr.reset_to_defaults()
            QMessageBox.information(self, "Reset Complete", "Settings reset to defaults.")
