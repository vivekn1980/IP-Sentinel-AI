"""Settings & Provider API Credentials Manager View screen."""

import logging
from typing import Dict, Tuple

from PySide6.QtCore import Slot
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
from ip_sentinel.core.worker import TaskPool
from ip_sentinel.providers.abuseipdb_provider import AbuseIPDBProvider
from ip_sentinel.providers.virustotal_provider import VirusTotalProvider

logger = logging.getLogger("ip_sentinel.ui.views.settings")


class SettingsView(QWidget):
    """View interface for managing application settings and API provider keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_mgr = ConfigManager()
        self.key_inputs: Dict[str, QLineEdit] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header Title
        title_label = QLabel("⚙️ Settings & Threat Intelligence Credentials")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        layout.addWidget(title_label)

        # Provider Key Manager Card
        key_card = QFrame()
        key_card.setProperty("class", "cardFrame")
        k_layout = QVBoxLayout(key_card)

        k_title = QLabel("Threat Intelligence Provider API Keys")
        k_title.setProperty("class", "cardHeader")
        k_layout.addWidget(k_title)

        k_desc = QLabel("API keys are saved securely in local credential storage. Never hardcoded or transmitted off-device:")
        k_desc.setStyleSheet("color: #94A3B8; margin-bottom: 10px;")
        k_layout.addWidget(k_desc)

        grid = QGridLayout()
        grid.setSpacing(10)

        providers = [
            ("mock", "Mock Engine (Deterministic)", "ACTIVE", False),
            ("abuseipdb", "AbuseIPDB API v2", "Passive Reputation Feed", True),
            ("virustotal", "VirusTotal v3 API", "Multi-Engine AV Feed", True),
            ("shodan", "Shodan Host API", "Deferred / Stub Interface", True),
            ("otx", "AlienVault OTX API", "Deferred / Stub Interface", True),
        ]

        for idx, (p_id, p_name, p_desc, requires_key) in enumerate(providers):
            lbl_name = QLabel(f"<b>{p_name}</b><br><span style='color: #64748B; font-size: 11px;'>{p_desc}</span>")

            grid.addWidget(lbl_name, idx, 0)

            if requires_key:
                inp = QLineEdit()
                inp.setEchoMode(QLineEdit.EchoMode.Password)
                inp.setPlaceholderText(f"Enter {p_name} API Key...")
                existing_key = self.config_mgr.secret_store.get_secret(p_id)
                if existing_key:
                    inp.setText(existing_key)
                self.key_inputs[p_id] = inp
                grid.addWidget(inp, idx, 1)

                btn_test = QPushButton("⚡ Test Connection")
                btn_test.setProperty("class", "secondaryButton")
                btn_test.clicked.connect(lambda checked, p=p_id: self._test_provider_connection(p))
                grid.addWidget(btn_test, idx, 2)
            else:
                lbl_na = QLabel("<span style='color: #34D399; font-weight: bold;'>[ALWAYS ACTIVE]</span>")
                grid.addWidget(lbl_na, idx, 1)

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

    def _test_provider_connection(self, provider_id: str):
        inp = self.key_inputs.get(provider_id)
        key_val = inp.text().strip() if inp else ""

        if not key_val:
            QMessageBox.warning(self, "API Key Required", f"Please enter a valid {provider_id.upper()} API key to test connection.")
            return

        # Temporarily set key in secret store for test
        self.config_mgr.secret_store.set_secret(provider_id, key_val)

        signals = TaskPool.execute(self._run_connection_test_task, provider_id)
        signals.result.connect(lambda res: self._on_test_result(provider_id, res))
        signals.error.connect(lambda err: QMessageBox.critical(self, "Test Error", str(err[1])))

    def _run_connection_test_task(self, provider_id: str) -> Tuple[bool, str]:
        if provider_id == "abuseipdb":
            prov = AbuseIPDBProvider(timeout=5.0)
            res = prov.query_ip("1.1.1.1")
            if res.status == res.status.AVAILABLE:
                return True, f"AbuseIPDB Connection Successful! Valid API key. (Response time: {res.execution_time_ms:.1f}ms)"
            else:
                return False, f"AbuseIPDB Test Failed: {res.error_message}"

        elif provider_id == "virustotal":
            prov = VirusTotalProvider(timeout=5.0)
            res = prov.query_ip("1.1.1.1")
            if res.status == res.status.AVAILABLE:
                return True, f"VirusTotal Connection Successful! Valid API key. (Response time: {res.execution_time_ms:.1f}ms)"
            else:
                return False, f"VirusTotal Test Failed: {res.error_message}"
        else:
            return False, f"Test connection not implemented for provider '{provider_id}'."

    def _on_test_result(self, provider_id: str, result_tuple: Tuple[bool, str]):
        success, msg = result_tuple
        if success:
            QMessageBox.information(self, f"{provider_id.upper()} Test Successful", msg)
        else:
            QMessageBox.warning(self, f"{provider_id.upper()} Test Failed", msg)

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
