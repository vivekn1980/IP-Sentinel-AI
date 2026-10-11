"""Origin IP & CDN Discovery View widget with Passive DNS and Port Banner Scanner."""

import logging
from typing import List
from PySide6.QtCore import Signal, Slot, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.signals import SignalBus
from ip_sentinel.core.worker import Worker
from ip_sentinel.models.origin_finder import (
    HistoricalDNSRecord,
    OriginDiscoveryResult,
    PortBanner,
    PortScanResult,
    SSLCertificateDetails,
)
from ip_sentinel.services.origin_ip_service import OriginIPService

logger = logging.getLogger("ip_sentinel.ui.views.origin_finder")


class OriginFinderView(QWidget):
    """View widget for discovering CDN IPs, candidate real Origin IPs, passive DNS history, and port banner inspection."""

    investigate_ip_requested = Signal(str)

    def __init__(self, service: OriginIPService = None):
        super().__init__()
        self.service = service or OriginIPService()
        self.current_result: OriginDiscoveryResult = None
        self.current_cert_result: SSLCertificateDetails = None
        self.current_pdns_records: List[HistoricalDNSRecord] = []
        self.current_port_result: PortScanResult = None
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # Header Title
        title_lbl = QLabel("Origin IP & Threat Hunting Workstation")
        title_lbl.setStyleSheet("color: #F8FAFC; font-size: 18px; font-weight: bold;")
        subtitle_lbl = QLabel(
            "Uncover real Origin IPs behind CDNs, explore Passive DNS history, grab server software banners, and inspect SSL/TLS certificates."
        )
        subtitle_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")

        main_layout.addWidget(title_lbl)
        main_layout.addWidget(subtitle_lbl)

        # Tab Widget organizing 4 key capabilities
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("originFinderTabs")

        # Tab 1: CDN & Origin IP Discovery
        self.tab_discovery = QWidget()
        self._setup_discovery_tab()
        self.tab_widget.addTab(self.tab_discovery, "🌐 Origin IP & CDN Bypass")

        # Tab 2: Passive DNS History
        self.tab_pdns = QWidget()
        self._setup_pdns_tab()
        self.tab_widget.addTab(self.tab_pdns, "🕰️ Passive DNS History")

        # Tab 3: Port & Banner Scanner
        self.tab_ports = QWidget()
        self._setup_ports_tab()
        self.tab_widget.addTab(self.tab_ports, "🔌 Port & Banner Scanner")

        # Tab 4: SSL/TLS Certificate & Expiry Inspector
        self.tab_cert = QWidget()
        self._setup_cert_inspector_tab()
        self.tab_widget.addTab(self.tab_cert, "🔐 SSL/TLS Certificate & Expiry Inspector")

        main_layout.addWidget(self.tab_widget, 1)

    # -------------------------------------------------------------------------
    # TAB 1: Origin IP & CDN Bypass Engine
    # -------------------------------------------------------------------------

    def _setup_discovery_tab(self):
        layout = QVBoxLayout(self.tab_discovery)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Control Card
        control_card = QFrame()
        control_card.setObjectName("cardFrame")
        control_card.setProperty("class", "cardFrame")
        ctrl_layout = QVBoxLayout(control_card)
        ctrl_layout.setSpacing(10)

        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        url_lbl = QLabel("Target Domain / URL:")
        url_lbl.setStyleSheet("color: #00E5FF; font-weight: bold;")

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target domain or URL (e.g. https://www.example.com/api or example.com)")
        self.url_input.returnPressed.connect(self.start_discovery)

        self.btn_scan = QPushButton("🔍 Start Origin Discovery")
        self.btn_scan.setProperty("class", "primaryButton")
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        self.btn_scan.clicked.connect(self.start_discovery)

        input_row.addWidget(url_lbl)
        input_row.addWidget(self.url_input, 1)
        input_row.addWidget(self.btn_scan)

        ctrl_layout.addLayout(input_row)

        headers_lbl = QLabel("Optional Raw Email Headers (for outgoing mail IP leak detection):")
        headers_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")

        self.txt_email_headers = QTextEdit()
        self.txt_email_headers.setMaximumHeight(50)
        self.txt_email_headers.setPlaceholderText("Paste raw Received: from email headers here to analyze SMTP origin server IPs...")

        ctrl_layout.addWidget(headers_lbl)
        ctrl_layout.addWidget(self.txt_email_headers)

        layout.addWidget(control_card)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(5)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Metric Cards Row
        metric_row = QHBoxLayout()
        metric_row.setSpacing(12)

        self.card_cdn_ips = self._create_metric_card("CDN Edge IPs", "0", "#38BDF8")
        self.card_candidates = self._create_metric_card("Candidates Probed", "0", "#FBBF24")
        self.card_origins = self._create_metric_card("Confirmed Origin IPs", "0", "#00E676")

        metric_row.addWidget(self.card_cdn_ips)
        metric_row.addWidget(self.card_candidates)
        metric_row.addWidget(self.card_origins)

        layout.addLayout(metric_row)

        # Results Splitter (Tables)
        splitter = QSplitter(Qt.Vertical)

        # Table 1: Resolved & CDN IPs
        cdn_box = QWidget()
        cdn_layout = QVBoxLayout(cdn_box)
        cdn_layout.setContentsMargins(0, 0, 0, 0)
        cdn_lbl = QLabel("Phase 1: Resolved Domain & CDN Edge IPs")
        cdn_lbl.setStyleSheet("color: #00E5FF; font-weight: bold; font-size: 13px;")

        self.table_cdn = QTableWidget(0, 3)
        self.table_cdn.setHorizontalHeaderLabels(["IP Address", "CDN Provider Status", "Matched Public CIDR Range"])
        self.table_cdn.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        cdn_layout.addWidget(cdn_lbl)
        cdn_layout.addWidget(self.table_cdn)
        splitter.addWidget(cdn_box)

        # Table 2: Candidate & Validated Origin IPs
        origin_box = QWidget()
        origin_layout = QVBoxLayout(origin_box)
        origin_layout.setContentsMargins(0, 0, 0, 0)
        origin_lbl = QLabel("Phase 2: Origin IP Candidates, Passive DNS & Host Header Validation")
        origin_lbl.setStyleSheet("color: #00E676; font-weight: bold; font-size: 13px;")

        self.table_origins = QTableWidget(0, 5)
        self.table_origins.setHorizontalHeaderLabels(["Candidate IP", "Discovery Source Method", "Host Header Match", "HTTP Response", "Actions"])
        self.table_origins.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_origins.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_origins.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_origins.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_origins.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)

        origin_layout.addWidget(origin_lbl)
        origin_layout.addWidget(self.table_origins)
        splitter.addWidget(origin_box)

        layout.addWidget(splitter, 1)

        # Favicon Hash Card
        fav_card = QFrame()
        fav_card.setObjectName("cardFrame")
        fav_layout = QHBoxLayout(fav_card)

        self.fav_status_lbl = QLabel("Favicon MMH3 Hash: Not Calculated")
        self.fav_status_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")

        self.btn_copy_shodan = QPushButton("📋 Copy Shodan Favicon Query")
        self.btn_copy_shodan.setProperty("class", "secondaryButton")
        self.btn_copy_shodan.setCursor(Qt.PointingHandCursor)
        self.btn_copy_shodan.setEnabled(False)
        self.btn_copy_shodan.clicked.connect(self._copy_shodan_query)

        fav_layout.addWidget(self.fav_status_lbl, 1)
        fav_layout.addWidget(self.btn_copy_shodan)

        layout.addWidget(fav_card)

    # -------------------------------------------------------------------------
    # TAB 2: Passive DNS History
    # -------------------------------------------------------------------------

    def _setup_pdns_tab(self):
        """Setup UI for Historical Passive DNS Explorer."""
        layout = QVBoxLayout(self.tab_pdns)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Control Card
        control_card = QFrame()
        control_card.setObjectName("cardFrame")
        control_card.setProperty("class", "cardFrame")
        ctrl_layout = QVBoxLayout(control_card)
        ctrl_layout.setSpacing(10)

        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        dom_lbl = QLabel("Target Domain:")
        dom_lbl.setStyleSheet("color: #00E5FF; font-weight: bold;")

        self.pdns_domain_input = QLineEdit()
        self.pdns_domain_input.setPlaceholderText("Enter domain name to query passive DNS history (e.g. example.com or cloudflare.com)")
        self.pdns_domain_input.returnPressed.connect(self.start_pdns_search)

        self.btn_pdns_search = QPushButton("🔍 Search Passive DNS")
        self.btn_pdns_search.setProperty("class", "primaryButton")
        self.btn_pdns_search.setCursor(Qt.PointingHandCursor)
        self.btn_pdns_search.clicked.connect(self.start_pdns_search)

        input_row.addWidget(dom_lbl)
        input_row.addWidget(self.pdns_domain_input, 1)
        input_row.addWidget(self.btn_pdns_search)

        ctrl_layout.addLayout(input_row)

        # Presets Row
        preset_row = QHBoxLayout()
        preset_row.setSpacing(8)
        p_lbl = QLabel("Quick Presets:")
        p_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
        preset_row.addWidget(p_lbl)

        for p_dom in ["example.com", "cloudflare.com", "github.com"]:
            btn_p = QPushButton(p_dom)
            btn_p.setProperty("class", "secondaryButton")
            btn_p.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            btn_p.clicked.connect(lambda _, d=p_dom: self.search_pdns_for_target(d))
            preset_row.addWidget(btn_p)

        preset_row.addStretch()
        ctrl_layout.addLayout(preset_row)

        layout.addWidget(control_card)

        # Progress Bar
        self.pdns_progress_bar = QProgressBar()
        self.pdns_progress_bar.setRange(0, 0)
        self.pdns_progress_bar.setTextVisible(False)
        self.pdns_progress_bar.setFixedHeight(5)
        self.pdns_progress_bar.hide()
        layout.addWidget(self.pdns_progress_bar)

        # Summary Info Label
        self.pdns_summary_lbl = QLabel("Enter a domain and click 'Search Passive DNS' to uncover historical IP addresses.")
        self.pdns_summary_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")
        layout.addWidget(self.pdns_summary_lbl)

        # Table of Passive DNS Records
        self.table_pdns = QTableWidget(0, 7)
        self.table_pdns.setHorizontalHeaderLabels(
            ["Hostname / Domain", "Historical IP", "First Seen", "Last Seen", "Source Archive", "CDN Status", "Actions"]
        )
        self.table_pdns.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_pdns.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_pdns.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_pdns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_pdns.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_pdns.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table_pdns.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)

        layout.addWidget(self.table_pdns, 1)

        # Bottom Actions Row
        pdns_bottom = QHBoxLayout()
        self.btn_copy_pdns = QPushButton("📋 Copy Historical DNS Table")
        self.btn_copy_pdns.setProperty("class", "secondaryButton")
        self.btn_copy_pdns.setEnabled(False)
        self.btn_copy_pdns.clicked.connect(self._copy_pdns_table)

        pdns_bottom.addWidget(self.btn_copy_pdns)
        pdns_bottom.addStretch()
        layout.addLayout(pdns_bottom)

    # -------------------------------------------------------------------------
    # TAB 3: Port & Banner Scanner
    # -------------------------------------------------------------------------

    def _setup_ports_tab(self):
        """Setup UI for Port and Service Software Banner Grabber."""
        layout = QVBoxLayout(self.tab_ports)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Control Card
        control_card = QFrame()
        control_card.setObjectName("cardFrame")
        control_card.setProperty("class", "cardFrame")
        ctrl_layout = QVBoxLayout(control_card)
        ctrl_layout.setSpacing(10)

        row1 = QHBoxLayout()
        row1.setSpacing(10)

        ip_lbl = QLabel("Target IP / Host:")
        ip_lbl.setStyleSheet("color: #00E5FF; font-weight: bold;")

        self.port_ip_input = QLineEdit()
        self.port_ip_input.setPlaceholderText("Enter candidate IP address (e.g. 1.1.1.1 or 192.168.1.1)")
        self.port_ip_input.returnPressed.connect(self.start_port_scan)

        ports_lbl = QLabel("Ports:")
        ports_lbl.setStyleSheet("color: #94A3B8; font-weight: bold;")

        self.port_list_input = QLineEdit("21, 22, 80, 443, 3306, 3389, 8080, 8443")
        self.port_list_input.setToolTip("Comma-separated ports to probe")

        self.btn_port_scan = QPushButton("🔌 Scan Ports & Grab Banners")
        self.btn_port_scan.setProperty("class", "primaryButton")
        self.btn_port_scan.setCursor(Qt.PointingHandCursor)
        self.btn_port_scan.clicked.connect(self.start_port_scan)

        row1.addWidget(ip_lbl)
        row1.addWidget(self.port_ip_input, 1)
        row1.addWidget(ports_lbl)
        row1.addWidget(self.port_list_input, 1)
        row1.addWidget(self.btn_port_scan)

        ctrl_layout.addLayout(row1)

        # Presets Row
        preset_row = QHBoxLayout()
        preset_row.setSpacing(8)
        pr_lbl = QLabel("Scan Profiles:")
        pr_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
        preset_row.addWidget(pr_lbl)

        profiles = [
            ("Standard Web & Mgmt (21, 22, 80, 443, 3306, 3389, 8080, 8443)", "21, 22, 80, 443, 3306, 3389, 8080, 8443"),
            ("Web Only (80, 443, 8080, 8443)", "80, 443, 8080, 8443"),
            ("Remote Admin (22, 3389, 9000, 8443)", "22, 3389, 9000, 8443"),
            ("Databases (3306, 5432, 6379, 27017)", "3306, 5432, 6379, 27017"),
        ]

        for prof_title, prof_ports in profiles:
            btn_pr = QPushButton(prof_title.split("(")[0].strip())
            btn_pr.setProperty("class", "secondaryButton")
            btn_pr.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            btn_pr.clicked.connect(lambda _, p=prof_ports: self.port_list_input.setText(p))
            preset_row.addWidget(btn_pr)

        preset_row.addStretch()
        ctrl_layout.addLayout(preset_row)

        layout.addWidget(control_card)

        # Progress Bar
        self.port_progress_bar = QProgressBar()
        self.port_progress_bar.setRange(0, 0)
        self.port_progress_bar.setTextVisible(False)
        self.port_progress_bar.setFixedHeight(5)
        self.port_progress_bar.hide()
        layout.addWidget(self.port_progress_bar)

        # Port Summary Card
        self.port_summary_card = QFrame()
        self.port_summary_card.setObjectName("cardFrame")
        self.port_summary_card.setStyleSheet("QFrame#cardFrame { background-color: #171E28; border: 1px solid #2A3649; border-radius: 8px; }")
        port_card_layout = QHBoxLayout(self.port_summary_card)
        port_card_layout.setContentsMargins(16, 10, 16, 10)

        self.port_status_badge = QLabel("NO PORTS SCANNED")
        self.port_status_badge.setStyleSheet("font-weight: bold; font-size: 12px; color: #94A3B8;")

        self.port_summary_lbl = QLabel("Enter target IP above to probe open services and software versions.")
        self.port_summary_lbl.setStyleSheet("color: #E2E8F0; font-size: 12px;")

        port_card_layout.addWidget(self.port_status_badge)
        port_card_layout.addWidget(self.port_summary_lbl, 1)

        layout.addWidget(self.port_summary_card)

        # Table of Scanned Ports
        self.table_ports = QTableWidget(0, 4)
        self.table_ports.setHorizontalHeaderLabels(["Port", "Service Name", "State", "Detected Software Banner / Response"])
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        layout.addWidget(self.table_ports, 1)

        # Bottom Buttons
        port_bottom = QHBoxLayout()
        self.btn_copy_ports = QPushButton("📋 Copy Port Banner Report")
        self.btn_copy_ports.setProperty("class", "secondaryButton")
        self.btn_copy_ports.setEnabled(False)
        self.btn_copy_ports.clicked.connect(self._copy_port_results)

        self.btn_investigate_port_ip = QPushButton("🔍 Investigate Target in Threat Intel")
        self.btn_investigate_port_ip.setProperty("class", "secondaryButton")
        self.btn_investigate_port_ip.setEnabled(False)
        self.btn_investigate_port_ip.clicked.connect(self._investigate_scanned_port_ip)

        port_bottom.addWidget(self.btn_copy_ports)
        port_bottom.addWidget(self.btn_investigate_port_ip)
        port_bottom.addStretch()

        layout.addLayout(port_bottom)

    # -------------------------------------------------------------------------
    # TAB 4: SSL/TLS Certificate & Expiry Inspector
    # -------------------------------------------------------------------------

    def _setup_cert_inspector_tab(self):
        """Setup UI for standalone SSL/TLS Certificate and Expiry Inspector."""
        layout = QVBoxLayout(self.tab_cert)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Control Card
        control_card = QFrame()
        control_card.setObjectName("cardFrame")
        control_card.setProperty("class", "cardFrame")
        ctrl_layout = QVBoxLayout(control_card)
        ctrl_layout.setSpacing(10)

        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        target_lbl = QLabel("Target Host / IP:")
        target_lbl.setStyleSheet("color: #00E5FF; font-weight: bold;")

        self.cert_target_input = QLineEdit()
        self.cert_target_input.setPlaceholderText("Enter domain (e.g. google.com) or candidate IP (e.g. 1.1.1.1 or 103.14.46.124)")
        self.cert_target_input.returnPressed.connect(self.start_cert_inspection)

        port_lbl = QLabel("Port:")
        port_lbl.setStyleSheet("color: #94A3B8; font-weight: bold;")

        self.cert_port_spin = QSpinBox()
        self.cert_port_spin.setRange(1, 65535)
        self.cert_port_spin.setValue(443)
        self.cert_port_spin.setFixedWidth(75)

        self.btn_inspect_cert = QPushButton("🔐 Inspect SSL Certificate")
        self.btn_inspect_cert.setProperty("class", "primaryButton")
        self.btn_inspect_cert.setCursor(Qt.PointingHandCursor)
        self.btn_inspect_cert.clicked.connect(self.start_cert_inspection)

        input_row.addWidget(target_lbl)
        input_row.addWidget(self.cert_target_input, 1)
        input_row.addWidget(port_lbl)
        input_row.addWidget(self.cert_port_spin)
        input_row.addWidget(self.btn_inspect_cert)

        ctrl_layout.addLayout(input_row)

        # Presets Row
        preset_row = QHBoxLayout()
        preset_row.setSpacing(8)
        preset_lbl = QLabel("Quick Presets:")
        preset_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
        preset_row.addWidget(preset_lbl)

        presets = [("1.1.1.1 (Cloudflare DNS)", "1.1.1.1"), ("google.com", "google.com"), ("github.com", "github.com"), ("8.8.8.8 (Google DNS)", "8.8.8.8")]
        for p_label, p_target in presets:
            btn_p = QPushButton(p_label)
            btn_p.setProperty("class", "secondaryButton")
            btn_p.setCursor(Qt.PointingHandCursor)
            btn_p.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            btn_p.clicked.connect(lambda _, t=p_target: self._set_cert_preset(t))
            preset_row.addWidget(btn_p)

        preset_row.addStretch()
        ctrl_layout.addLayout(preset_row)

        layout.addWidget(control_card)

        # Progress Bar
        self.cert_progress_bar = QProgressBar()
        self.cert_progress_bar.setRange(0, 0)
        self.cert_progress_bar.setTextVisible(False)
        self.cert_progress_bar.setFixedHeight(5)
        self.cert_progress_bar.hide()
        layout.addWidget(self.cert_progress_bar)

        # Scroll Area for Details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(12)

        # Status Banner Card
        self.cert_status_card = QFrame()
        self.cert_status_card.setObjectName("cardFrame")
        self.cert_status_card.setStyleSheet("QFrame#cardFrame { background-color: #171E28; border: 1px solid #2A3649; border-radius: 8px; }")
        status_card_layout = QHBoxLayout(self.cert_status_card)
        status_card_layout.setContentsMargins(16, 12, 16, 12)

        self.cert_status_badge = QLabel("NO CERTIFICATE INSPECTED")
        self.cert_status_badge.setProperty("class", "badgeCertValid")
        self.cert_status_badge.setStyleSheet("font-weight: bold; font-size: 13px;")

        self.cert_expiry_summary = QLabel("Enter a domain or IP address above and click 'Inspect SSL Certificate'.")
        self.cert_expiry_summary.setStyleSheet("color: #E2E8F0; font-size: 13px; font-weight: 500;")

        status_card_layout.addWidget(self.cert_status_badge)
        status_card_layout.addWidget(self.cert_expiry_summary, 1)

        scroll_layout.addWidget(self.cert_status_card)

        # Certificate Details Grid Card
        self.cert_details_card = QFrame()
        self.cert_details_card.setObjectName("cardFrame")
        self.cert_details_card.setStyleSheet("QFrame#cardFrame { background-color: #171E28; border: 1px solid #2A3649; border-radius: 8px; }")
        grid_layout = QGridLayout(self.cert_details_card)
        grid_layout.setContentsMargins(16, 14, 16, 14)
        grid_layout.setSpacing(10)

        def make_row(row_idx, label_text):
            lbl_name = QLabel(label_text)
            lbl_name.setStyleSheet("color: #94A3B8; font-weight: bold; font-size: 12px; min-width: 140px;")
            lbl_val = QLabel("—")
            lbl_val.setStyleSheet("color: #F8FAFC; font-size: 12px; font-family: monospace;")
            lbl_val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid_layout.addWidget(lbl_name, row_idx, 0)
            grid_layout.addWidget(lbl_val, row_idx, 1)
            return lbl_val

        self.lbl_cert_target = make_row(0, "Target & Port:")
        self.lbl_cert_cn = make_row(1, "Common Name (CN):")
        self.lbl_cert_issuer_org = make_row(2, "Issuer Organization:")
        self.lbl_cert_issuer_cn = make_row(3, "Issuer Common Name:")
        self.lbl_cert_valid_from = make_row(4, "Valid From (notBefore):")
        self.lbl_cert_valid_to = make_row(5, "Valid Until (notAfter):")
        self.lbl_cert_days_remaining = make_row(6, "Days Remaining:")
        self.lbl_cert_tls_version = make_row(7, "TLS Protocol Version:")
        self.lbl_cert_cipher = make_row(8, "Cipher Suite:")
        self.lbl_cert_serial = make_row(9, "Serial Number:")
        self.lbl_cert_fingerprint = make_row(10, "SHA-256 Fingerprint:")

        scroll_layout.addWidget(self.cert_details_card)

        # Subject Alternative Names (SANs) Card
        sans_card = QFrame()
        sans_card.setObjectName("cardFrame")
        sans_card.setStyleSheet("QFrame#cardFrame { background-color: #171E28; border: 1px solid #2A3649; border-radius: 8px; }")
        sans_layout = QVBoxLayout(sans_card)
        sans_layout.setContentsMargins(16, 12, 16, 12)
        sans_layout.setSpacing(8)

        self.lbl_sans_header = QLabel("Subject Alternative Names (SANs):")
        self.lbl_sans_header.setStyleSheet("color: #00E5FF; font-weight: bold; font-size: 12px;")

        self.txt_cert_sans = QTextEdit()
        self.txt_cert_sans.setReadOnly(True)
        self.txt_cert_sans.setMaximumHeight(85)
        self.txt_cert_sans.setStyleSheet("background-color: #0F172A; color: #E2E8F0; font-family: monospace; font-size: 11px; border: 1px solid #2A3649; border-radius: 4px;")
        self.txt_cert_sans.setPlaceholderText("No Subject Alternative Names parsed yet.")

        sans_layout.addWidget(self.lbl_sans_header)
        sans_layout.addWidget(self.txt_cert_sans)

        scroll_layout.addWidget(sans_card)

        # Bottom Actions Row
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        self.btn_copy_cert = QPushButton("📋 Copy Certificate Details")
        self.btn_copy_cert.setProperty("class", "secondaryButton")
        self.btn_copy_cert.setCursor(Qt.PointingHandCursor)
        self.btn_copy_cert.setEnabled(False)
        self.btn_copy_cert.clicked.connect(self._copy_cert_details)

        self.btn_investigate_cert_target = QPushButton("🔍 Investigate Target in Threat Intel")
        self.btn_investigate_cert_target.setProperty("class", "secondaryButton")
        self.btn_investigate_cert_target.setCursor(Qt.PointingHandCursor)
        self.btn_investigate_cert_target.setEnabled(False)
        self.btn_investigate_cert_target.clicked.connect(self._investigate_cert_target)

        actions_row.addWidget(self.btn_copy_cert)
        actions_row.addWidget(self.btn_investigate_cert_target)
        actions_row.addStretch()

        scroll_layout.addLayout(actions_row)
        scroll_layout.addStretch()

        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, 1)

    def _set_cert_preset(self, target: str):
        self.cert_target_input.setText(target)
        self.cert_port_spin.setValue(443)
        self.start_cert_inspection()

    def _create_metric_card(self, title: str, default_val: str, color: str) -> QFrame:
        card = QFrame()
        card.setObjectName("cardFrame")
        card.setStyleSheet("QFrame#cardFrame { background-color: #171E28; border: 1px solid #2A3649; border-radius: 8px; }")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: bold;")
        v_lbl = QLabel(default_val)
        v_lbl.setObjectName("valLabel")
        v_lbl.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold;")

        layout.addWidget(t_lbl)
        layout.addWidget(v_lbl)
        return card

    def _update_card_val(self, card: QFrame, val: str):
        v_lbl = card.findChild(QLabel, "valLabel")
        if v_lbl:
            v_lbl.setText(val)

    # -------------------------------------------------------------------------
    # Discovery Execution
    # -------------------------------------------------------------------------

    def start_discovery(self):
        target_text = self.url_input.text().strip()
        if not target_text:
            return

        self.btn_scan.setEnabled(False)
        self.progress_bar.show()

        email_headers = self.txt_email_headers.toPlainText().strip() or None

        worker = Worker(self.service.run_discovery, target_text, email_headers)
        worker.signals.result.connect(self._on_discovery_finished)
        worker.signals.error.connect(self._on_discovery_error)

        from PySide6.QtCore import QThreadPool
        SignalBus.instance().worker_started.emit("Origin IP & CDN Discovery Scan")
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _on_discovery_finished(self, result: OriginDiscoveryResult):
        self.btn_scan.setEnabled(True)
        self.progress_bar.hide()
        self.current_result = result
        SignalBus.instance().worker_finished.emit()

        # Update metric cards
        self._update_card_val(self.card_cdn_ips, str(len(result.cdn_ips)))
        self._update_card_val(self.card_candidates, str(len(result.candidate_origins)))
        self._update_card_val(self.card_origins, str(len(result.validated_origins)))

        # Render Table 1 (CDN IPs)
        self.table_cdn.setRowCount(0)
        for cdn_res in result.cdn_ips:
            row = self.table_cdn.rowCount()
            self.table_cdn.insertRow(row)

            ip_item = QTableWidgetItem(cdn_res.ip)
            ip_item.setTextAlignment(Qt.AlignCenter)
            self.table_cdn.setItem(row, 0, ip_item)

            if cdn_res.is_cdn:
                status_item = QTableWidgetItem(f"🛡️ CDN ({cdn_res.provider})")
                status_item.setForeground(Qt.GlobalColor.cyan)
                cidr_item = QTableWidgetItem(cdn_res.matched_cidr or "Known Range")
            else:
                status_item = QTableWidgetItem("Direct IP (Non-CDN)")
                status_item.setForeground(Qt.GlobalColor.green)
                cidr_item = QTableWidgetItem("N/A")

            status_item.setTextAlignment(Qt.AlignCenter)
            cidr_item.setTextAlignment(Qt.AlignCenter)

            self.table_cdn.setItem(row, 1, status_item)
            self.table_cdn.setItem(row, 2, cidr_item)

        # Render Table 2 (Origin Candidates & Validated)
        self.table_origins.setRowCount(0)
        for cand in result.candidate_origins:
            row = self.table_origins.rowCount()
            self.table_origins.insertRow(row)

            ip_item = QTableWidgetItem(cand.ip)
            ip_item.setTextAlignment(Qt.AlignCenter)

            src_item = QTableWidgetItem(cand.discovery_source)

            if cand.validated:
                match_item = QTableWidgetItem("✓ CONFIRMED MATCH")
                match_item.setForeground(Qt.GlobalColor.green)
            else:
                match_item = QTableWidgetItem("UNVERIFIED / FAILED")
                match_item.setForeground(Qt.GlobalColor.yellow)

            match_item.setTextAlignment(Qt.AlignCenter)

            resp_item = QTableWidgetItem(cand.response_snippet or "No response")

            # Actions Cell Widget: Investigate, Cert, and Ports buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(5)

            btn_inv = QPushButton("🔍 Investigate")
            btn_inv.setProperty("class", "secondaryButton")
            btn_inv.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_inv.clicked.connect(lambda _, ip=cand.ip: self.investigate_ip_requested.emit(ip))

            btn_cert = QPushButton("🔐 Cert")
            btn_cert.setProperty("class", "secondaryButton")
            btn_cert.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_cert.clicked.connect(lambda _, ip=cand.ip: self.inspect_cert_for_target(ip, 443))

            btn_ports = QPushButton("🔌 Ports")
            btn_ports.setProperty("class", "secondaryButton")
            btn_ports.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_ports.clicked.connect(lambda _, ip=cand.ip: self.scan_ports_for_target(ip))

            action_layout.addWidget(btn_inv)
            action_layout.addWidget(btn_cert)
            action_layout.addWidget(btn_ports)

            self.table_origins.setItem(row, 0, ip_item)
            self.table_origins.setItem(row, 1, src_item)
            self.table_origins.setItem(row, 2, match_item)
            self.table_origins.setItem(row, 3, resp_item)
            self.table_origins.setCellWidget(row, 4, action_widget)

        # Update Favicon Shodan Info
        if result.favicon_result and result.favicon_result.shodan_query:
            self.fav_status_lbl.setText(
                f"Favicon MMH3 Hash: {result.favicon_result.mmh3_hash}  |  Shodan Query: {result.favicon_result.shodan_query}"
            )
            self.btn_copy_shodan.setEnabled(True)
        else:
            err = result.favicon_result.error if result.favicon_result else "Not calculated"
            self.fav_status_lbl.setText(f"Favicon Hash: {err}")
            self.btn_copy_shodan.setEnabled(False)

        # Pre-fill Passive DNS tab if records found
        if result.historical_dns:
            self.current_pdns_records = result.historical_dns
            self._render_pdns_table(result.historical_dns)

    @Slot(Exception)
    def _on_discovery_error(self, err: Exception):
        self.btn_scan.setEnabled(True)
        self.progress_bar.hide()
        SignalBus.instance().worker_finished.emit()
        logger.error(f"Origin discovery error: {err}")

    def _copy_shodan_query(self):
        if self.current_result and self.current_result.favicon_result and self.current_result.favicon_result.shodan_query:
            q = self.current_result.favicon_result.shodan_query
            QApplication.clipboard().setText(q)
            self.btn_copy_shodan.setText("✓ Copied to Clipboard!")

    # -------------------------------------------------------------------------
    # Passive DNS Logic
    # -------------------------------------------------------------------------

    def search_pdns_for_target(self, domain: str):
        self.tab_widget.setCurrentIndex(1)
        self.pdns_domain_input.setText(domain)
        self.start_pdns_search()

    def start_pdns_search(self):
        domain = self.pdns_domain_input.text().strip()
        if not domain:
            return

        self.btn_pdns_search.setEnabled(False)
        self.pdns_progress_bar.show()

        worker = Worker(self.service.fetch_passive_dns_history, domain)
        worker.signals.result.connect(self._on_pdns_finished)
        worker.signals.error.connect(self._on_pdns_error)

        from PySide6.QtCore import QThreadPool
        SignalBus.instance().worker_started.emit(f"Passive DNS lookup for {domain}")
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _on_pdns_finished(self, records: List[HistoricalDNSRecord]):
        self.btn_pdns_search.setEnabled(True)
        self.pdns_progress_bar.hide()
        self.current_pdns_records = records
        SignalBus.instance().worker_finished.emit()
        self._render_pdns_table(records)

    def _render_pdns_table(self, records: List[HistoricalDNSRecord]):
        self.table_pdns.setRowCount(0)
        non_cdn_count = sum(1 for r in records if not r.is_cdn)
        self.pdns_summary_lbl.setText(
            f"Retrieved {len(records)} historical DNS records. Found {non_cdn_count} non-CDN candidate Origin IPs."
        )

        for rec in records:
            row = self.table_pdns.rowCount()
            self.table_pdns.insertRow(row)

            self.table_pdns.setItem(row, 0, QTableWidgetItem(rec.domain))

            ip_item = QTableWidgetItem(rec.ip)
            ip_item.setTextAlignment(Qt.AlignCenter)
            self.table_pdns.setItem(row, 1, ip_item)

            first_item = QTableWidgetItem(rec.first_seen or "—")
            first_item.setTextAlignment(Qt.AlignCenter)
            self.table_pdns.setItem(row, 2, first_item)

            last_item = QTableWidgetItem(rec.last_seen or "—")
            last_item.setTextAlignment(Qt.AlignCenter)
            self.table_pdns.setItem(row, 3, last_item)

            src_item = QTableWidgetItem(rec.source)
            src_item.setTextAlignment(Qt.AlignCenter)
            self.table_pdns.setItem(row, 4, src_item)

            if rec.is_cdn:
                cdn_item = QTableWidgetItem(f"🛡️ CDN ({rec.cdn_provider})")
                cdn_item.setForeground(Qt.GlobalColor.cyan)
            else:
                cdn_item = QTableWidgetItem("🎯 Potential Real Origin (Non-CDN)")
                cdn_item.setForeground(Qt.GlobalColor.green)

            cdn_item.setTextAlignment(Qt.AlignCenter)
            self.table_pdns.setItem(row, 5, cdn_item)

            # Actions Cell
            act_widget = QWidget()
            act_layout = QHBoxLayout(act_widget)
            act_layout.setContentsMargins(4, 2, 4, 2)
            act_layout.setSpacing(5)

            btn_inv = QPushButton("🔍 Investigate")
            btn_inv.setProperty("class", "secondaryButton")
            btn_inv.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_inv.clicked.connect(lambda _, ip=rec.ip: self.investigate_ip_requested.emit(ip))

            btn_ports = QPushButton("🔌 Ports")
            btn_ports.setProperty("class", "secondaryButton")
            btn_ports.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_ports.clicked.connect(lambda _, ip=rec.ip: self.scan_ports_for_target(ip))

            btn_cert = QPushButton("🔐 Cert")
            btn_cert.setProperty("class", "secondaryButton")
            btn_cert.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            btn_cert.clicked.connect(lambda _, ip=rec.ip: self.inspect_cert_for_target(ip, 443))

            act_layout.addWidget(btn_inv)
            act_layout.addWidget(btn_ports)
            act_layout.addWidget(btn_cert)

            self.table_pdns.setCellWidget(row, 6, act_widget)

        self.btn_copy_pdns.setEnabled(len(records) > 0)

    @Slot(Exception)
    def _on_pdns_error(self, err: Exception):
        self.btn_pdns_search.setEnabled(True)
        self.pdns_progress_bar.hide()
        SignalBus.instance().worker_finished.emit()
        self.pdns_summary_lbl.setText(f"Error querying passive DNS: {err}")
        logger.error(f"Passive DNS lookup error: {err}")

    def _copy_pdns_table(self):
        if not self.current_pdns_records:
            return
        lines = ["Domain\tIP\tFirstSeen\tLastSeen\tSource\tCDN"]
        for r in self.current_pdns_records:
            cdn_str = r.cdn_provider if r.is_cdn else "Non-CDN"
            lines.append(f"{r.domain}\t{r.ip}\t{r.first_seen}\t{r.last_seen}\t{r.source}\t{cdn_str}")
        QApplication.clipboard().setText("\n".join(lines))
        self.btn_copy_pdns.setText("✓ Copied Passive DNS Table!")

    # -------------------------------------------------------------------------
    # Port Scanner Logic
    # -------------------------------------------------------------------------

    def scan_ports_for_target(self, ip: str):
        self.tab_widget.setCurrentIndex(2)
        self.port_ip_input.setText(ip)
        self.start_port_scan()

    def start_port_scan(self):
        ip = self.port_ip_input.text().strip()
        if not ip:
            return

        # Parse ports string
        ports_str = self.port_list_input.text().strip()
        ports_to_scan = []
        if ports_str:
            for part in ports_str.replace(" ", "").split(","):
                try:
                    p_val = int(part)
                    if 1 <= p_val <= 65535:
                        ports_to_scan.append(p_val)
                except ValueError:
                    pass

        if not ports_to_scan:
            ports_to_scan = OriginIPService.DEFAULT_SCAN_PORTS

        self.btn_port_scan.setEnabled(False)
        self.port_progress_bar.show()

        worker = Worker(self.service.scan_ports_and_banners, ip, ports_to_scan, 1.5)
        worker.signals.result.connect(self._on_port_scan_finished)
        worker.signals.error.connect(self._on_port_scan_error)

        from PySide6.QtCore import QThreadPool
        SignalBus.instance().worker_started.emit(f"Port & Banner Scan on {ip}")
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _on_port_scan_finished(self, result: PortScanResult):
        self.btn_port_scan.setEnabled(True)
        self.port_progress_bar.hide()
        self.current_port_result = result
        SignalBus.instance().worker_finished.emit()

        open_ports = [p for p in result.open_ports if p.state == "OPEN"]
        self.port_status_badge.setText(f"{len(open_ports)} OPEN PORTS DETECTED")
        if open_ports:
            self.port_status_badge.setStyleSheet("font-weight: bold; font-size: 12px; color: #00E676;")
        else:
            self.port_status_badge.setStyleSheet("font-weight: bold; font-size: 12px; color: #F87171;")

        self.port_summary_lbl.setText(
            f"Probed {len(result.scanned_ports)} ports on {result.ip} in {result.execution_time_seconds}s. Found {len(open_ports)} open services."
        )

        self.table_ports.setRowCount(0)
        for p in result.open_ports:
            row = self.table_ports.rowCount()
            self.table_ports.insertRow(row)

            port_item = QTableWidgetItem(str(p.port))
            port_item.setTextAlignment(Qt.AlignCenter)
            self.table_ports.setItem(row, 0, port_item)

            svc_item = QTableWidgetItem(f"{p.service_name} (SSL)" if p.is_ssl else p.service_name)
            svc_item.setTextAlignment(Qt.AlignCenter)
            self.table_ports.setItem(row, 1, svc_item)

            state_item = QTableWidgetItem(p.state)
            state_item.setTextAlignment(Qt.AlignCenter)
            if p.state == "OPEN":
                state_item.setForeground(Qt.GlobalColor.green)
            elif p.state == "FILTERED":
                state_item.setForeground(Qt.GlobalColor.yellow)
            else:
                state_item.setForeground(Qt.GlobalColor.gray)
            self.table_ports.setItem(row, 2, state_item)

            banner_item = QTableWidgetItem(p.banner)
            self.table_ports.setItem(row, 3, banner_item)

        self.btn_copy_ports.setEnabled(True)
        self.btn_investigate_port_ip.setEnabled(True)

    @Slot(Exception)
    def _on_port_scan_error(self, err: Exception):
        self.btn_port_scan.setEnabled(True)
        self.port_progress_bar.hide()
        SignalBus.instance().worker_finished.emit()
        self.port_status_badge.setText("ERROR")
        self.port_summary_lbl.setText(f"Scan failed: {err}")
        logger.error(f"Port scan error: {err}")

    def _copy_port_results(self):
        if not self.current_port_result:
            return
        lines = [f"Port Scan Report for {self.current_port_result.ip}"]
        for p in self.current_port_result.open_ports:
            lines.append(f"Port {p.port} ({p.service_name}): {p.state} - {p.banner}")
        QApplication.clipboard().setText("\n".join(lines))
        self.btn_copy_ports.setText("✓ Copied Port Results!")

    def _investigate_scanned_port_ip(self):
        if self.current_port_result and self.current_port_result.ip:
            self.investigate_ip_requested.emit(self.current_port_result.ip)

    # -------------------------------------------------------------------------
    # Certificate Inspector Logic
    # -------------------------------------------------------------------------

    def inspect_cert_for_target(self, target: str, port: int = 443):
        self.tab_widget.setCurrentIndex(3)
        self.cert_target_input.setText(target)
        self.cert_port_spin.setValue(port)
        self.start_cert_inspection()

    def start_cert_inspection(self):
        target = self.cert_target_input.text().strip()
        if not target:
            return

        port = self.cert_port_spin.value()
        self.btn_inspect_cert.setEnabled(False)
        self.cert_progress_bar.show()

        worker = Worker(self.service.inspect_certificate, target, port)
        worker.signals.result.connect(self._on_cert_inspection_finished)
        worker.signals.error.connect(self._on_cert_inspection_error)

        from PySide6.QtCore import QThreadPool
        SignalBus.instance().worker_started.emit(f"SSL Certificate Inspection for {target}:{port}")
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _on_cert_inspection_finished(self, cert: SSLCertificateDetails):
        self.btn_inspect_cert.setEnabled(True)
        self.cert_progress_bar.hide()
        self.current_cert_result = cert
        SignalBus.instance().worker_finished.emit()

        if cert.status == "VALID":
            self.cert_status_badge.setText(f"🟢 VALID CERTIFICATE ({cert.days_remaining} Days Remaining)")
            self.cert_status_badge.setProperty("class", "badgeCertValid")
            self.cert_expiry_summary.setText(f"Certificate is trusted and active. Expires on {cert.valid_to} UTC.")
            self.cert_expiry_summary.setStyleSheet("color: #34D399; font-size: 13px; font-weight: bold;")
        elif cert.status == "EXPIRING_SOON":
            self.cert_status_badge.setText(f"🟡 EXPIRING SOON ({cert.days_remaining} Days Remaining)")
            self.cert_status_badge.setProperty("class", "badgeCertExpiring")
            self.cert_expiry_summary.setText(f"⚠️ Certificate expires very soon on {cert.valid_to} UTC!")
            self.cert_expiry_summary.setStyleSheet("color: #FBBF24; font-size: 13px; font-weight: bold;")
        elif cert.status == "EXPIRED":
            expired_ago = abs(cert.days_remaining)
            self.cert_status_badge.setText(f"🔴 EXPIRED ({expired_ago} Days Ago)")
            self.cert_status_badge.setProperty("class", "badgeCertExpired")
            self.cert_expiry_summary.setText(f"⛔ Certificate has EXPIRED on {cert.valid_to} UTC!")
            self.cert_expiry_summary.setStyleSheet("color: #FCA5A5; font-size: 13px; font-weight: bold;")
        else:
            self.cert_status_badge.setText("⚠️ ERROR / UNABLE TO INSPECT")
            self.cert_status_badge.setProperty("class", "badgeCertError")
            err_msg = cert.error or "Handshake or connection failure."
            self.cert_expiry_summary.setText(f"Error: {err_msg}")
            self.cert_expiry_summary.setStyleSheet("color: #F472B6; font-size: 13px; font-weight: bold;")

        self.cert_status_badge.style().unpolish(self.cert_status_badge)
        self.cert_status_badge.style().polish(self.cert_status_badge)

        self.lbl_cert_target.setText(f"{cert.target}:{cert.port}")
        self.lbl_cert_cn.setText(cert.common_name or "—")
        self.lbl_cert_issuer_org.setText(cert.issuer_org or "—")
        self.lbl_cert_issuer_cn.setText(cert.issuer_cn or "—")
        self.lbl_cert_valid_from.setText(cert.valid_from or "—")
        self.lbl_cert_valid_to.setText(cert.valid_to or "—")
        self.lbl_cert_days_remaining.setText(f"{cert.days_remaining} days" if cert.status != "ERROR" else "—")
        self.lbl_cert_tls_version.setText(cert.tls_version or "—")
        self.lbl_cert_cipher.setText(cert.cipher_suite or "—")
        self.lbl_cert_serial.setText(cert.serial_number or "—")
        self.lbl_cert_fingerprint.setText(cert.sha256_fingerprint or "—")

        if cert.sans:
            self.lbl_sans_header.setText(f"Subject Alternative Names (SANs) ({len(cert.sans)} total):")
            self.txt_cert_sans.setPlainText(", ".join(cert.sans))
        else:
            self.lbl_sans_header.setText("Subject Alternative Names (SANs):")
            self.txt_cert_sans.setPlainText("None reported by certificate." if cert.status != "ERROR" else "N/A")

        self.btn_copy_cert.setEnabled(cert.status != "ERROR")
        self.btn_investigate_cert_target.setEnabled(True)

    @Slot(Exception)
    def _on_cert_inspection_error(self, err: Exception):
        self.btn_inspect_cert.setEnabled(True)
        self.cert_progress_bar.hide()
        SignalBus.instance().worker_finished.emit()
        self.cert_status_badge.setText("⚠️ ERROR")
        self.cert_status_badge.setProperty("class", "badgeCertError")
        self.cert_expiry_summary.setText(f"Connection/TLS Error: {err}")
        self.cert_expiry_summary.setStyleSheet("color: #F472B6; font-size: 13px; font-weight: bold;")
        logger.error(f"Certificate inspection error: {err}")

    def _copy_cert_details(self):
        if not self.current_cert_result:
            return
        c = self.current_cert_result
        details_text = (
            f"=== SSL/TLS Certificate Analysis Report ===\n"
            f"Target: {c.target}:{c.port}\n"
            f"Status: {c.status} ({c.days_remaining} days remaining)\n"
            f"Common Name: {c.common_name}\n"
            f"Issuer: {c.issuer_org} ({c.issuer_cn})\n"
            f"Validity Window: {c.valid_from} -> {c.valid_to}\n"
            f"TLS Version: {c.tls_version}\n"
            f"Cipher Suite: {c.cipher_suite}\n"
            f"SHA-256 Fingerprint: {c.sha256_fingerprint}\n"
            f"Serial Number: {c.serial_number}\n"
            f"SANs ({len(c.sans)}): {', '.join(c.sans)}\n"
        )
        QApplication.clipboard().setText(details_text)
        self.btn_copy_cert.setText("✓ Copied Certificate Details!")

    def _investigate_cert_target(self):
        target = self.cert_target_input.text().strip()
        if target:
            host, _ = OriginIPService._parse_target_host_port(target)
            self.investigate_ip_requested.emit(host)
