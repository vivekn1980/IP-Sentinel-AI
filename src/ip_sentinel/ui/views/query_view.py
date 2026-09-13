"""IP Threat Intelligence Query & Investigation View screen."""

import logging
from typing import Optional, Tuple

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
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
    """Investigation view interface for looking up IP threat intelligence."""

    def __init__(self, service: Optional[InvestigationService] = None, parent=None):
        super().__init__(parent)
        self.service = service or InvestigationService()
        self.current_result: Optional[IPIntelResult] = None
        self._setup_ui()
        
        # Connect to global signal bus for quick lookup triggers
        SignalBus.instance().investigation_started.connect(self.set_ip_and_investigate)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header Title
        title_label = QLabel("🔍 IP Threat Intelligence Investigation")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        layout.addWidget(title_label)

        # Search Input Bar Panel
        search_card = QFrame()
        search_card.setProperty("class", "cardFrame")
        s_layout = QHBoxLayout(search_card)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IPv4 or IPv6 Address (e.g. 185.220.101.5, 1.1.1.1)...")
        self.ip_input.returnPressed.connect(self.start_investigation)

        self.btn_investigate = QPushButton("⚡ Investigate IP")
        self.btn_investigate.setProperty("class", "primaryButton")
        self.btn_investigate.clicked.connect(self.start_investigation)

        s_layout.addWidget(self.ip_input, 4)
        s_layout.addWidget(self.btn_investigate, 1)
        layout.addWidget(search_card)

        # Progress Bar Widget (Hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Results Summary Header Card
        self.result_card = QFrame()
        self.result_card.setProperty("class", "cardFrame")
        self.result_card.setVisible(False)
        r_layout = QHBoxLayout(self.result_card)

        # Threat Badge & Score Display
        self.threat_badge = QLabel("CLEAN")
        self.threat_badge.setProperty("class", "badgeClean")
        
        self.score_label = QLabel("Risk Score: 0 / 100")
        self.score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F8FAFC;")

        self.target_label = QLabel("Target: 0.0.0.0")
        self.target_label.setStyleSheet("color: #94A3B8; font-size: 14px;")

        self.btn_export_quick = QPushButton("📄 Export Report")
        self.btn_export_quick.setProperty("class", "secondaryButton")
        self.btn_export_quick.clicked.connect(self._go_to_reports)

        r_layout.addWidget(self.threat_badge)
        r_layout.addWidget(self.score_label)
        r_layout.addWidget(self.target_label)
        r_layout.addStretch()
        r_layout.addWidget(self.btn_export_quick)

        layout.addWidget(self.result_card)

        # Evidence Table Card
        self.table_card = QFrame()
        self.table_card.setProperty("class", "cardFrame")
        self.table_card.setVisible(False)
        t_layout = QVBoxLayout(self.table_card)

        t_title = QLabel("Structured Threat Evidence Telemetry")
        t_title.setProperty("class", "cardHeader")
        t_layout.addWidget(t_title)

        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(4)
        self.evidence_table.setHorizontalHeaderLabels(["Severity", "Category", "Source", "Description"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        t_layout.addWidget(self.evidence_table)

        layout.addWidget(self.table_card)
        layout.addStretch()

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
        self.result_card.setVisible(False)
        self.table_card.setVisible(False)

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

        # Populate Evidence Table
        self.evidence_table.setRowCount(0)
        for item in result.aggregated_evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)

            self.evidence_table.setItem(row, 0, QTableWidgetItem(item.severity))
            self.evidence_table.setItem(row, 1, QTableWidgetItem(item.category))
            self.evidence_table.setItem(row, 2, QTableWidgetItem(item.source))
            self.evidence_table.setItem(row, 3, QTableWidgetItem(item.description))

        self.result_card.setVisible(True)
        self.table_card.setVisible(True)

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
