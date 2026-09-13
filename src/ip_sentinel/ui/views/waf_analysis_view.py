"""PySide6 View for WAF Log Analysis and Behavioral Investigation."""

import os
import logging
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.worker import Worker
from ip_sentinel.models.waf_behavior import WAFAnalysisResult, WAFIPAnalysis
from ip_sentinel.services.waf_analysis_service import WAFAnalysisService

logger = logging.getLogger("ip_sentinel.ui.views.waf_analysis")


class WAFAnalysisView(QWidget):
    """View for uploading WAF log files (CSV/JSON), viewing summary metrics, and analyzing IP traffic patterns."""

    # Signal emitted when user selects an IP and clicks "Investigate Selected IP"
    investigate_ip_requested = Signal(str, object)  # (ip_address, WAFIPAnalysis object)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.waf_service = WAFAnalysisService()
        self.current_result: Optional[WAFAnalysisResult] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header Title & Description
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()

        title_label = QLabel("WAF Behavioral & Attack Analysis Engine")
        title_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        desc_label = QLabel("Upload WAF log telemetry (CSV / JSON) to detect automated bots, web scanners, HTTP floods, and credential attacks.")
        desc_label.setStyleSheet("font-size: 13px; color: #94a3b8;")

        title_box.addWidget(title_label)
        title_box.addWidget(desc_label)

        # Action Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(12)

        self.btn_upload_csv = QPushButton("📁 Upload WAF CSV")
        self.btn_upload_csv.setCursor(Qt.PointingHandCursor)
        self.btn_upload_csv.setStyleSheet(
            "QPushButton { background-color: #0284c7; color: white; border-radius: 6px; padding: 10px 16px; font-weight: bold; }"
            "QPushButton:hover { background-color: #0369a1; }"
        )
        self.btn_upload_csv.clicked.connect(self._upload_csv)

        self.btn_upload_json = QPushButton("📄 Upload WAF JSON")
        self.btn_upload_json.setCursor(Qt.PointingHandCursor)
        self.btn_upload_json.setStyleSheet(
            "QPushButton { background-color: #4f46e5; color: white; border-radius: 6px; padding: 10px 16px; font-weight: bold; }"
            "QPushButton:hover { background-color: #4338ca; }"
        )
        self.btn_upload_json.clicked.connect(self._upload_json)

        btn_box.addWidget(self.btn_upload_csv)
        btn_box.addWidget(self.btn_upload_json)

        header_layout.addLayout(title_box)
        header_layout.addStretch()
        header_layout.addLayout(btn_box)
        layout.addLayout(header_layout)

        # Status & File Label
        self.status_label = QLabel("No WAF log file loaded. Select a CSV or JSON file to begin analysis.")
        self.status_label.setStyleSheet("color: #64748b; font-style: italic; font-size: 12px;")
        layout.addWidget(self.status_label)

        # Summary Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_events = self._create_card("TOTAL EVENTS", "0", "#38bdf8")
        self.card_ips = self._create_card("UNIQUE IPS", "0", "#a855f7")
        self.card_time = self._create_card("TIME RANGE", "N/A", "#10b981")
        self.card_high_risk = self._create_card("HIGH RISK IPS", "0", "#ef4444")

        cards_layout.addWidget(self.card_events["frame"])
        cards_layout.addWidget(self.card_ips["frame"])
        cards_layout.addWidget(self.card_time["frame"])
        cards_layout.addWidget(self.card_high_risk["frame"])
        layout.addLayout(cards_layout)

        # Interactive Results Table & Toolbar Header
        tbl_header_layout = QHBoxLayout()
        tbl_title = QLabel("Analyzed IP Addresses & Threat Classifications")
        tbl_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #f8fafc;")

        self.btn_investigate = QPushButton("⚡ Investigate Selected IP")
        self.btn_investigate.setEnabled(False)
        self.btn_investigate.setCursor(Qt.PointingHandCursor)
        self.btn_investigate.setStyleSheet(
            "QPushButton { background-color: #059669; color: white; border-radius: 6px; padding: 8px 14px; font-weight: bold; }"
            "QPushButton:hover { background-color: #047857; }"
            "QPushButton:disabled { background-color: #334155; color: #64748b; }"
        )
        self.btn_investigate.clicked.connect(self._on_investigate_selected)

        tbl_header_layout.addWidget(tbl_title)
        tbl_header_layout.addStretch()
        tbl_header_layout.addWidget(self.btn_investigate)
        layout.addLayout(tbl_header_layout)

        # QTableWidget
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Source IP", "Requests", "Peak Rate", "4xx %", "5xx %", "Primary Classification", "Confidence", "Risk Score"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setStyleSheet(
            "QTableWidget { background-color: #0f172a; color: #f8fafc; gridline-color: #334155; border: 1px solid #334155; border-radius: 8px; }"
            "QHeaderView::section { background-color: #1e293b; color: #38bdf8; font-weight: bold; padding: 6px; border: none; }"
            "QTableWidget::item:selected { background-color: #334155; color: #38bdf8; }"
        )
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self.table)

    def _create_card(self, title: str, initial_val: str, accent_color: str) -> dict:
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background-color: #1e293b; border-radius: 8px; border-left: 5px solid {accent_color}; padding: 12px; }}"
        )
        c_layout = QVBoxLayout(frame)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(4)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("font-size: 11px; color: #94a3b8; font-weight: bold;")
        v_lbl = QLabel(initial_val)
        v_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {accent_color};")

        c_layout.addWidget(t_lbl)
        c_layout.addWidget(v_lbl)
        return {"frame": frame, "val_label": v_lbl}

    def _upload_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open WAF CSV Log File", "", "CSV Files (*.csv);;All Files (*)")
        if file_path:
            self._process_file(file_path, self.waf_service.csv_parser)

    def _upload_json(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open WAF JSON Log File", "", "JSON Files (*.json *.jsonl);;All Files (*)")
        if file_path:
            self._process_file(file_path, self.waf_service.json_parser)

    def _process_file(self, file_path: str, parser):
        self.status_label.setText(f"Processing WAF log file: '{os.path.basename(file_path)}'...")
        self.btn_upload_csv.setEnabled(False)
        self.btn_upload_json.setEnabled(False)

        def worker_fn():
            return self.waf_service.analyze_file(file_path, parser=parser)

        worker = Worker(worker_fn)
        worker.signals.result.connect(self._on_analysis_complete)
        worker.signals.error.connect(self._on_analysis_error)
        from PySide6.QtCore import QThreadPool
        QThreadPool.globalInstance().start(worker)

    def _on_analysis_complete(self, result: WAFAnalysisResult):
        self.current_result = result
        self.btn_upload_csv.setEnabled(True)
        self.btn_upload_json.setEnabled(True)

        self.status_label.setText(f"Analysis complete for '{os.path.basename(result.file_path)}'. Found {result.total_events} events across {result.unique_ips_count} unique IP(s).")
        self.card_events["val_label"].setText(str(result.total_events))
        self.card_ips["val_label"].setText(str(result.unique_ips_count))

        time_str = "N/A"
        if result.time_range_start and result.time_range_end:
            time_str = f"{result.time_range_start[:10]} .. {result.time_range_end[11:16]}"
        self.card_time["val_label"].setText(time_str)
        self.card_high_risk["val_label"].setText(str(len(result.high_risk_ips)))

        # Populate Table
        self.table.setRowCount(0)
        for row_idx, ip_an in enumerate(result.top_ips):
            self.table.insertRow(row_idx)
            self.table.setItem(row_idx, 0, QTableWidgetItem(ip_an.source_ip))
            self.table.setItem(row_idx, 1, QTableWidgetItem(str(ip_an.total_requests)))
            self.table.setItem(row_idx, 2, QTableWidgetItem(f"{ip_an.peak_req_per_sec:.1f} req/s"))
            self.table.setItem(row_idx, 3, QTableWidgetItem(f"{ip_an.pct_4xx:.1f}%"))
            self.table.setItem(row_idx, 4, QTableWidgetItem(f"{ip_an.pct_5xx:.1f}%"))
            
            cls_item = QTableWidgetItem(ip_an.primary_classification.value)
            if ip_an.primary_classification.value in ("WEB_SCANNER", "CREDENTIAL_ATTACK", "HTTP_FLOOD", "MALICIOUS_BOT"):
                cls_item.setForeground(Qt.red)
            elif ip_an.primary_classification.value in ("AUTOMATED_BOT", "SUSPICIOUS_AUTOMATION"):
                cls_item.setForeground(Qt.yellow)
            else:
                cls_item.setForeground(Qt.green)
            self.table.setItem(row_idx, 5, cls_item)

            self.table.setItem(row_idx, 6, QTableWidgetItem(f"{ip_an.classification_confidence}%"))
            
            score_item = QTableWidgetItem(f"{ip_an.risk_score}/100")
            if ip_an.risk_score >= 70:
                score_item.setForeground(Qt.red)
            elif ip_an.risk_score >= 40:
                score_item.setForeground(Qt.yellow)
            else:
                score_item.setForeground(Qt.green)
            self.table.setItem(row_idx, 7, score_item)

    def _on_analysis_error(self, err_tuple):
        err_msg = err_tuple[1]
        logger.error(f"WAF log analysis error: {err_msg}")
        self.status_label.setText(f"Error reading WAF log: {err_msg}")
        self.btn_upload_csv.setEnabled(True)
        self.btn_upload_json.setEnabled(True)

    def _on_selection_changed(self):
        selected_rows = self.table.selectedItems()
        self.btn_investigate.setEnabled(len(selected_rows) > 0)

    def _on_investigate_selected(self):
        selected_items = self.table.selectedItems()
        if not selected_items or not self.current_result:
            return

        row = self.table.currentRow()
        ip_item = self.table.item(row, 0)
        if not ip_item:
            return

        target_ip = ip_item.text().strip()
        ip_an = self.current_result.ip_analyses.get(target_ip)
        logger.info(f"User requested investigation for WAF IP: {target_ip}")
        self.investigate_ip_requested.emit(target_ip, ip_an)
