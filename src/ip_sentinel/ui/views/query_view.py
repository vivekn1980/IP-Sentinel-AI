"""IP Threat Intelligence & Evidence Correlation Query View screen."""

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
    """Investigation view interface displaying passive network intelligence, threat feeds, and evidence correlation."""

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
        title_label = QLabel("🔍 Passive IP Threat Intelligence & Evidence Correlation")
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

        self.threat_badge = QLabel("VERY_LOW")
        self.threat_badge.setProperty("class", "badgeClean")

        self.score_label = QLabel("Risk Score: 0 / 100")
        self.score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F8FAFC;")

        self.confidence_label = QLabel("Confidence: 90%")
        self.confidence_label.setStyleSheet("color: #00E5FF; font-size: 14px; font-weight: 500;")

        self.target_label = QLabel("Target: 0.0.0.0")
        self.target_label.setStyleSheet("color: #94A3B8; font-size: 14px;")

        self.btn_export_quick = QPushButton("📄 Export Report")
        self.btn_export_quick.setProperty("class", "secondaryButton")
        self.btn_export_quick.clicked.connect(self._go_to_reports)

        rh_layout.addWidget(self.threat_badge)
        rh_layout.addWidget(self.score_label)
        rh_layout.addWidget(self.confidence_label)
        rh_layout.addWidget(self.target_label)
        rh_layout.addStretch()
        rh_layout.addWidget(self.btn_export_quick)

        self.results_layout.addWidget(self.result_header_card)

        # Contradictory Evidence Banner (Hidden by default)
        self.conflict_banner = QLabel()
        self.conflict_banner.setWordWrap(True)
        self.conflict_banner.setStyleSheet(
            "background-color: #78350F; color: #FDE68A; border: 1px solid #D97706; padding: 10px; border-radius: 6px; font-weight: bold;"
        )
        self.conflict_banner.setVisible(False)
        self.results_layout.addWidget(self.conflict_banner)

        # 2. EVIDENCE SUMMARY PILLS CARD
        self.ev_summary_card = QFrame()
        self.ev_summary_card.setProperty("class", "cardFrame")
        es_layout = QHBoxLayout(self.ev_summary_card)
        es_layout.addWidget(QLabel("<b>EVIDENCE SUMMARY:</b>"))

        self.pill_crit = QLabel("Critical: 0")
        self.pill_crit.setStyleSheet("color: #F87171; font-weight: bold; background: #7F1D1D; padding: 4px 8px; border-radius: 4px;")
        self.pill_high = QLabel("High: 0")
        self.pill_high.setStyleSheet("color: #FCA5A5; font-weight: bold; background: #78350F; padding: 4px 8px; border-radius: 4px;")
        self.pill_med = QLabel("Medium: 0")
        self.pill_med.setStyleSheet("color: #FDE68A; font-weight: bold; background: #78350F; padding: 4px 8px; border-radius: 4px;")
        self.pill_info = QLabel("Info: 0")
        self.pill_info.setStyleSheet("color: #34D399; font-weight: bold; background: #064E3B; padding: 4px 8px; border-radius: 4px;")

        es_layout.addWidget(self.pill_crit)
        es_layout.addWidget(self.pill_high)
        es_layout.addWidget(self.pill_med)
        es_layout.addWidget(self.pill_info)
        es_layout.addStretch()

        self.results_layout.addWidget(self.ev_summary_card)

        # 3. THREAT INTELLIGENCE PROVIDERS ROW (AbuseIPDB & VirusTotal)
        prov_row = QHBoxLayout()
        prov_row.setSpacing(14)

        # AbuseIPDB Card
        self.abuse_card = QFrame()
        self.abuse_card.setProperty("class", "cardFrame")
        ab_layout = QVBoxLayout(self.abuse_card)
        ab_title = QLabel("🛡️ AbuseIPDB Telemetry")
        ab_title.setProperty("class", "cardHeader")
        ab_layout.addWidget(ab_title)
        self.abuse_grid = QGridLayout()
        ab_layout.addLayout(self.abuse_grid)
        prov_row.addWidget(self.abuse_card)

        # VirusTotal Card
        self.vt_card = QFrame()
        self.vt_card.setProperty("class", "cardFrame")
        vt_layout = QVBoxLayout(self.vt_card)
        vt_title = QLabel("🦠 VirusTotal Telemetry")
        vt_title.setProperty("class", "cardHeader")
        vt_layout.addWidget(vt_title)
        self.vt_grid = QGridLayout()
        vt_layout.addLayout(self.vt_grid)
        prov_row.addWidget(self.vt_card)

        self.results_layout.addLayout(prov_row)

        # 4. IP INFORMATION & NETWORK Cards (Grid Row)
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

        # 5. GEOLOCATION & RDAP Row
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

        # 6. DNS INFORMATION Card
        self.dns_card = QFrame()
        self.dns_card.setProperty("class", "cardFrame")
        dns_layout = QVBoxLayout(self.dns_card)
        dns_title = QLabel("📡 DNS TELEMETRY")
        dns_title.setProperty("class", "cardHeader")
        dns_layout.addWidget(dns_title)
        self.dns_grid = QGridLayout()
        dns_layout.addLayout(self.dns_grid)
        self.results_layout.addWidget(self.dns_card)

        # 7. Evidence Table Card
        self.table_card = QFrame()
        self.table_card.setProperty("class", "cardFrame")
        t_layout = QVBoxLayout(self.table_card)
        t_title = QLabel("Structured Threat & Network Evidence Table")
        t_title.setProperty("class", "cardHeader")
        t_layout.addWidget(t_title)

        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(5)
        self.evidence_table.setHorizontalHeaderLabels(["Source", "Category", "Severity", "Confidence", "Observation"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
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

        waf_analysis = getattr(self, "current_waf_analysis", None)

        # Execute in background thread pool to keep UI responsive
        signals = TaskPool.execute(self.service.investigate, ip_str, None, waf_analysis)
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
        self.confidence_label.setText(f"Confidence: {result.overall_threat_score.confidence}%")
        self.threat_badge.setText(level.value)

        if level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            self.threat_badge.setProperty("class", "badgeMalicious")
        elif level == ThreatLevel.MEDIUM:
            self.threat_badge.setProperty("class", "badgeSuspicious")
        else:
            self.threat_badge.setProperty("class", "badgeClean")

        self.threat_badge.style().unpolish(self.threat_badge)
        self.threat_badge.style().polish(self.threat_badge)

        # Contradictory Evidence Banner
        if result.has_conflicting_evidence and result.conflict_explanation:
            self.conflict_banner.setText(f"⚠️ {result.conflict_explanation}")
            self.conflict_banner.setVisible(True)
        else:
            self.conflict_banner.setVisible(False)

        # Evidence Summary Pills
        s = result.evidence_summary
        self.pill_crit.setText(f"Critical: {s.critical_count}")
        self.pill_high.setText(f"High: {s.high_count}")
        self.pill_med.setText(f"Medium: {s.medium_count}")
        self.pill_info.setText(f"Info: {s.info_count}")

        # AbuseIPDB Grid
        self._clear_grid(self.abuse_grid)
        ab_res = result.provider_results.get("abuseipdb")
        if ab_res:
            self._add_grid_row(self.abuse_grid, 0, "Status:", ab_res.status.value, is_status=True)
            if ab_res.reputation:
                self._add_grid_row(self.abuse_grid, 1, "Abuse Score:", f"{ab_res.reputation.abuse_score}%")
                self._add_grid_row(self.abuse_grid, 2, "Total Reports:", str(ab_res.reputation.total_reports))
                self._add_grid_row(self.abuse_grid, 3, "Reporters:", str(ab_res.reputation.distinct_reporters))
                self._add_grid_row(self.abuse_grid, 4, "Last Activity:", ab_res.reputation.last_reported_at or "N/A")
            else:
                self._add_grid_row(self.abuse_grid, 1, "Info:", ab_res.error_message or "Unconfigured")
        else:
            self._add_grid_row(self.abuse_grid, 0, "Status:", "NOT_CONFIGURED", is_status=True)

        # VirusTotal Grid
        self._clear_grid(self.vt_grid)
        vt_res = result.provider_results.get("virustotal")
        if vt_res:
            self._add_grid_row(self.vt_grid, 0, "Status:", vt_res.status.value, is_status=True)
            if vt_res.reputation:
                self._add_grid_row(self.vt_grid, 1, "Malicious Engines:", str(vt_res.reputation.malicious_count))
                self._add_grid_row(self.vt_grid, 2, "Suspicious Engines:", str(vt_res.reputation.suspicious_count))
                self._add_grid_row(self.vt_grid, 3, "Harmless / Clean:", str(vt_res.reputation.harmless_count))
                self._add_grid_row(self.vt_grid, 4, "Undetected:", str(vt_res.reputation.undetected_count))
            else:
                self._add_grid_row(self.vt_grid, 1, "Info:", vt_res.error_message or "Unconfigured")
        else:
            self._add_grid_row(self.vt_grid, 0, "Status:", "NOT_CONFIGURED", is_status=True)

        # IP Information Grid
        self._clear_grid(self.ip_grid)
        ip_version = 6 if ":" in result.target_ip else 4
        self._add_grid_row(self.ip_grid, 0, "IP Address:", result.target_ip)
        self._add_grid_row(self.ip_grid, 1, "IP Version:", f"IPv{ip_version}")
        self._add_grid_row(self.ip_grid, 2, "Public / Private:", "Private (RFC 1918)" if result.is_private_ip else "Public Address")
        self._add_grid_row(self.ip_grid, 3, "Reserved IP:", "Yes" if result.is_private_ip else "No")
        self._add_grid_row(self.ip_grid, 4, "Loopback IP:", "Yes" if result.is_loopback_ip else "No")
        self._add_grid_row(self.ip_grid, 5, "Status:", "AVAILABLE", is_status=True)

        # Network & ASN Grid
        self._clear_grid(self.net_grid)
        asn_str = f"AS{result.asn_data.asn}" if result.asn_data.asn is not None else "UNAVAILABLE"
        self._add_grid_row(self.net_grid, 0, "ASN:", asn_str)
        self._add_grid_row(self.net_grid, 1, "Organization:", result.asn_data.asn_org or result.geoip.asn_org or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 2, "Network / Prefix:", result.rdap.cidr or result.asn_data.network_prefix or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 3, "Registry:", result.rdap.registry or result.asn_data.registry or "UNAVAILABLE")
        self._add_grid_row(self.net_grid, 4, "Status:", result.asn_data.status.value, is_status=True)

        # Geolocation Grid
        self._clear_grid(self.geo_grid)
        self._add_grid_row(self.geo_grid, 0, "Country:", f"{result.geoip.country_name} ({result.geoip.country_code})" if result.geoip.country_name else "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 1, "Region / State:", result.geoip.region or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 2, "City:", result.geoip.city or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 3, "Timezone:", result.geoip.timezone or "UNAVAILABLE")
        self._add_grid_row(self.geo_grid, 4, "Status:", result.geoip.status.value, is_status=True)
        self.geo_disclaimer_lbl.setText(result.geoip.disclaimer)

        # RDAP Grid
        self._clear_grid(self.rdap_grid)
        self._add_grid_row(self.rdap_grid, 0, "Network Name:", result.rdap.network_name or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 1, "CIDR Range:", result.rdap.cidr or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 2, "Organization:", result.rdap.organization or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 3, "Abuse Contact:", result.rdap.abuse_contact or "UNAVAILABLE")
        self._add_grid_row(self.rdap_grid, 4, "Status:", result.rdap.status.value, is_status=True)

        # DNS Grid
        self._clear_grid(self.dns_grid)
        self._add_grid_row(self.dns_grid, 0, "Reverse PTR:", result.dns.hostname or (", ".join(result.dns.ptr_records) if result.dns.ptr_records else "UNAVAILABLE"))
        self._add_grid_row(self.dns_grid, 1, "A Records:", ", ".join(result.dns.a_records) if result.dns.a_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 2, "AAAA Records:", ", ".join(result.dns.aaaa_records) if result.dns.aaaa_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 3, "MX Records:", ", ".join(result.dns.mx_records) if result.dns.mx_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 4, "NS Records:", ", ".join(result.dns.ns_records) if result.dns.ns_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 5, "TXT Records:", ", ".join(result.dns.txt_records) if result.dns.txt_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 6, "CNAME Records:", ", ".join(result.dns.cname_records) if result.dns.cname_records else "UNAVAILABLE")
        self._add_grid_row(self.dns_grid, 7, "Status:", result.dns.status.value, is_status=True)

        # Populate Evidence Table
        self.evidence_table.setRowCount(0)
        for item in result.aggregated_evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            self.evidence_table.setItem(row, 0, QTableWidgetItem(item.source))
            self.evidence_table.setItem(row, 1, QTableWidgetItem(item.category))
            self.evidence_table.setItem(row, 2, QTableWidgetItem(item.severity))
            self.evidence_table.setItem(row, 3, QTableWidgetItem(f"{item.confidence}%"))
            self.evidence_table.setItem(row, 4, QTableWidgetItem(item.observation))

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
            elif val == "RATE_LIMITED":
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
