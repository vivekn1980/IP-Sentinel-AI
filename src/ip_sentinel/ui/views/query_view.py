"""IP Threat Intelligence & Network Query View screen."""

import logging
from typing import Optional, Tuple

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.signals import SignalBus
from ip_sentinel.core.worker import TaskPool
from ip_sentinel.models.threat_intel import IPIntelResult, ThreatLevel
from ip_sentinel.services.investigation_service import InvestigationService

logger = logging.getLogger("ip_sentinel.ui.views.query")


class QueryView(QWidget):
    """Investigation view interface for looking up real passive IP intelligence."""

    def __init__(self, service: Optional[InvestigationService] = None, parent=None):
        super().__init__(parent)
        self.service = service or InvestigationService()
        self.current_result: Optional[IPIntelResult] = None
        self._setup_ui()

        # Connect to global signal bus for quick lookup triggers
        SignalBus.instance().investigation_started.connect(self.set_ip_and_investigate)

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # Header Title
        title_label = QLabel("🔍 Passive IP & Network Intelligence Investigation")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        main_layout.addWidget(title_label)

        # Search Input Bar Panel
        search_card = QFrame()
        search_card.setProperty("class", "cardFrame")
        s_layout = QHBoxLayout(search_card)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter public IPv4 or IPv6 Address (e.g. 1.1.1.1, 8.8.8.8, 185.220.101.5)...")
        self.ip_input.returnPressed.connect(self.start_investigation)

        self.btn_investigate = QPushButton("⚡ Analyze IP")
        self.btn_investigate.setProperty("class", "primaryButton")
        self.btn_investigate.clicked.connect(self.start_investigation)

        s_layout.addWidget(self.ip_input, 4)
        s_layout.addWidget(self.btn_investigate, 1)
        main_layout.addWidget(search_card)

        # Progress Bar Widget
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Scrollable Area for Investigation Results
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")

        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(14)

        # 1. Threat Summary Header Card
        self.result_header_card = QFrame()
        self.result_header_card.setProperty("class", "cardFrame")
        rh_layout = QHBoxLayout(self.result_header_card)

        self.threat_badge = QLabel("CLEAN")
        self.threat_badge.setProperty("class", "badgeClean")

        self.score_label = QLabel("Risk Score: 0 / 100")
        self.score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F8FAFC;")

        self.target_label = QLabel("Target: 0.0.0.0")
        self.target_label.setStyleSheet("color: #94A3B8; font-size: 14px;")

        self.btn_export_quick = QPushButton("📄 Export Report")
        self.btn_export_quick.setProperty("class", "secondaryButton")
        self.btn_export_quick.clicked.connect(self._go_to_reports)

        rh_layout.addWidget(self.threat_badge)
        rh_layout.addWidget(self.score_label)
        rh_layout.addWidget(self.target_label)
        rh_layout.addStretch()
        rh_layout.addWidget(self.btn_export_quick)

        self.results_layout.addWidget(self.result_header_card)

        # 2. IP INFORMATION & NETWORK Cards (Grid Row)
        ip_net_row = QHBoxLayout()
        ip_net_row.setSpacing(14)

        # IP Information Card
        self.ip_info_card = QFrame()
        self.ip_info_card.setProperty("class", "cardFrame")
        ip_layout = QVBoxLayout(self.ip_info_card)
        ip_title = QLabel("📌 IP INFORMATION")
        ip_title.setProperty("class", "cardHeader")
        ip_layout.addWidget(ip_title)
        self.ip_grid = QGridLayout()
        ip_layout.addLayout(self.ip_grid)
        ip_net_row.addWidget(self.ip_info_card)

        # Network & ASN Card
        self.net_card = QFrame()
        self.net_card.setProperty("class", "cardFrame")
        net_layout = QVBoxLayout(self.net_card)
        net_title = QLabel("🌐 NETWORK & ASN")
        net_title.setProperty("class", "cardHeader")
        net_layout.addWidget(net_title)
        self.net_grid = QGridLayout()
        net_layout.addLayout(self.net_grid)
        ip_net_row.addWidget(self.net_card)

        self.results_layout.addLayout(ip_net_row)

        # 3. GEOLOCATION & RDAP Row
        geo_rdap_row = QHBoxLayout()
        geo_rdap_row.setSpacing(14)

        # Geolocation Card
        self.geo_card = QFrame()
        self.geo_card.setProperty("class", "cardFrame")
        geo_layout = QVBoxLayout(self.geo_card)
        geo_title = QLabel("📍 GEOLOCATION")
        geo_title.setProperty("class", "cardHeader")
        geo_layout.addWidget(geo_title)
        self.geo_grid = QGridLayout()
        geo_layout.addLayout(self.geo_grid)
        
        self.geo_disclaimer_lbl = QLabel()
        self.geo_disclaimer_lbl.setWordWrap(True)
        self.geo_disclaimer_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-style: italic; margin-top: 6px;")
        geo_layout.addWidget(self.geo_disclaimer_lbl)
        geo_rdap_row.addWidget(self.geo_card)

        # RDAP Details Card
        self.rdap_card = QFrame()
        self.rdap_card.setProperty("class", "cardFrame")
        rdap_layout = QVBoxLayout(self.rdap_card)
        rdap_title = QLabel("📋 RDAP REGISTRATION")
        rdap_title.setProperty("class", "cardHeader")
        rdap_layout.addWidget(rdap_title)
        self.rdap_grid = QGridLayout()
        rdap_layout.addLayout(self.rdap_grid)
        geo_rdap_row.addWidget(self.rdap_card)

        self.results_layout.addLayout(geo_rdap_row)

        # 4. DNS INFORMATION Card
        self.dns_card = QFrame()
        self.dns_card.setProperty("class", "cardFrame")
        dns_layout = QVBoxLayout(self.dns_card)
        dns_title = QLabel("📡 DNS TELEMETRY")
        dns_title.setProperty("class", "cardHeader")
        dns_layout.addWidget(dns_title)
        self.dns_grid = QGridLayout()
        dns_layout.addLayout(self.dns_grid)
        self.results_layout.addWidget(self.dns_card)

        # 5. Evidence Table Card
        self.table_card = QFrame()
        self.table_card.setProperty("class", "cardFrame")
        t_layout = QVBoxLayout(self.table_card)
        t_title = QLabel("Structured Threat Evidence")
        t_title.setProperty("class", "cardHeader")
        t_layout.addWidget(t_title)

        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(4)
        self.evidence_table.setHorizontalHeaderLabels(["Severity", "Category", "Source", "Description"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        t_layout.addWidget(self.evidence_table)
        self.results_layout.addWidget(self.table_card)

        self.scroll_area.setWidget(self.results_container)
        self.scroll_area.setVisible(False)
        main_layout.addWidget(self.scroll_area)

    @Slot(str)
    def set_ip_and_investigate(self, ip_str: str):
        """Set IP line edit and trigger investigation asynchronously."""
        self.ip_input.setText(ip_str)
        self.start_investigation()

    def start_investigation(self):
        """Validate input and submit task to background QThreadPool worker."""
        ip_str = self.ip_input.text().strip()
        if not ip_str:
            QMessageBox.warning(self, "Input Required", "Please enter a valid IP address.")
            return

        self.btn_investigate.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.scroll_area.setVisible(False)

        # Execute in background thread pool to keep UI responsive
        signals = TaskPool.execute(self.service.investigate, ip_str)
        signals.progress.connect(self._on_progress)
        signals.result.connect(self._on_result)
        signals.error.connect(self._on_error)
        signals.finished.connect(self._on_finished)

    @Slot(int, str)
    def _on_progress(self, percent: int, msg: str):
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"{msg} ({percent}%)")

    @Slot(object)
    def _on_result(self, result: IPIntelResult):
        self.current_result = result
        SignalBus.instance().investigation_completed.emit(result)

        self.target_label.setText(f"Target: {result.target_ip} ({result.investigation_id})")
        score = result.overall_threat_score.score
        level = result.overall_threat_score.level

        self.score_label.setText(f"Risk Score: {score} / 100")
        self.threat_badge.setText(level.value)

        if level == ThreatLevel.MALICIOUS:
            self.threat_badge.setProperty("class", "badgeMalicious")
        elif level == ThreatLevel.SUSPICIOUS:
            self.threat_badge.setProperty("class", "badgeSuspicious")
        else:
            self.threat_badge.setProperty("class", "badgeClean")

        self.threat_badge.style().unpolish(self.threat_badge)
        self.threat_badge.style().polish(self.threat_badge)

        # 1. Populate IP INFORMATION Grid
        self._clear_grid(self.ip_grid)
        ip_version = 6 if ":" in result.target_ip else 4
        self._add_grid_row(self.ip_grid, 0, "IP Address:", result.target_ip)
        self._add_grid_row(self.ip_grid, 1, "IP Version:", f"IPv{ip_version}")
        self._add_grid_row(self.ip_grid, 2, "Public / Private:", "Private (RFC 1918)" if result.is_private_ip else "Public Address")
        self._add_grid_row(self.ip_grid, 3, "Reserved IP:", "Yes" if result.is_private_ip else "No")
        self._add_grid_row(self.ip_grid, 4, "Loopback IP:", "Yes" if result.is_loopback_ip else "No")
        self._add_grid_row(self.ip_grid, 5, "Status:", "AVAILABLE", is_status=True)

        # 2. Populate NETWORK & ASN Grid
        self._clear_grid(self.net_grid)
        asn_str = f"AS{result.asn_data.asn}" if result.asn_data.asn is not None else "UNAVAILABLE"
        self._add_grid_row(self.net_grid, 0, "ASN:", asn_str)
        self._add_grid_row(self.net_grid, 1, "Organization:", result.asn_data.asn_org or result.geoip.asn_org or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 2, "Network / Prefix:", result.rdap.cidr or result.asn_data.network_prefix or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 3, "Registry:", result.rdap.registry or result.asn_data.registry or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 4, "Status:", result.asn_data.status.value, is_status=True)

        # 3. Populate GEOLOCATION Grid
        self._clear_grid(self.geo_grid)
        self._add_grid_row(self.geo_grid, 0, "Country:", f"{result.geoip.country_name} ({result.geoip.country_code})" if result.geoip.country_name else "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 1, "Region / State:", result.geoip.region or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 2, "City:", result.geoip.city or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 3, "Timezone:", result.geoip.timezone or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 4, "Status:", result.geoip.status.value, is_status=True)
        self.geo_disclaimer_lbl.setText(result.geoip.disclaimer)

        # 4. Populate RDAP Grid
        self._clear_grid(self.rdap_grid)
        self._add_grid_row(self.rdap_grid, 0, "Network Name:", result.rdap.network_name or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 1, "CIDR Range:", result.rdap.cidr or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 2, "Organization:", result.rdap.organization or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 3, "Abuse Contact:", result.rdap.abuse_contact or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 4, "Status:", result.rdap.status.value, is_status=True)

        # 5. Populate DNS Grid
        self._clear_grid(self.dns_grid)
        self._add_grid_row(self.dns_grid, 0, "Reverse DNS (PTR):", result.dns.hostname or (", ".join(result.dns.ptr_records) if result.dns.ptr_records else "UNAVAILABLE"))
        self._add_grid_row(self.dns_grid, 1, "A Records:", ", ".join(result.dns.a_records) if result.dns.a_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 2, "AAAA Records:", ", ".join(result.dns.aaaa_records) if result.dns.aaaa_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 3, "MX Records:", ", ".join(result.dns.mx_records) if result.dns.mx_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 4, "NS Records:", ", ".join(result.dns.ns_records) if result.dns.ns_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 5, "TXT Records:", ", ".join(result.dns.txt_records) if result.dns.txt_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 6, "CNAME Records:", ", ".join(result.dns.cname_records) if result.dns.cname_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 7, "Status:", result.dns.status.value, is_status=True)

        # 6. Populate Evidence Table
        self.evidence_table.setRowCount(0)
        for item in result.aggregated_evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            self.evidence_table.setItem(row, 0, QTableWidgetItem(item.severity))
            self.evidence_table.setItem(row, 1, QTableWidgetItem(item.category))
            self.evidence_table.setItem(row, 2, QTableWidgetItem(item.source))
            self.evidence_table.setItem(row, 3, QTableWidgetItem(item.description))

        self.scroll_area.setVisible(True)

    def _clear_grid(self, grid: QGridLayout):
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _add_grid_row(self, grid: QGridLayout, row: int, label: str, val: str, is_status: bool = False):
        lbl = QLabel(f"<b>{label}</b>")
        lbl.setStyleSheet("color: #94A3B8;")

        val_lbl = QLabel(val)
        if is_status:
            if val == "AVAILABLE":
                val_lbl.setStyleSheet("color: #34D399; font-weight: bold;")
            elif val == "ERROR":
                val_lbl.setStyleSheet("color: #F87171; font-weight: bold;")
            else:
                val_lbl.setStyleSheet("color: #FBBF24; font-weight: bold;")
        else:
            val_lbl.setStyleSheet("color: #F8FAFC;")
            val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        grid.addWidget(lbl, row, 0)
        grid.addWidget(val_lbl, row, 1)

    @Slot(tuple)
    def _on_error(self, err_tuple: Tuple):
        exctype, val, tb = err_tuple
        logger.error(f"Investigation failed: {val}")
        QMessageBox.critical(self, "Investigation Error", str(val))

    @Slot()
    def _on_finished(self):
        self.btn_investigate.setEnabled(True)
        self.progress_bar.setVisible(False)

    def _go_to_reports(self):
        SignalBus.instance().navigation_requested.emit("reports")
