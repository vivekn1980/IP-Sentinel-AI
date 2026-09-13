"""Reports Export View screen for generating HTML and PDF reports."""

import logging
import os
from pathlib import Path
from typing import Callable, Optional, Tuple

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.config import ConfigManager
from ip_sentinel.core.signals import SignalBus
from ip_sentinel.core.worker import TaskPool
from ip_sentinel.models.report_model import ReportData, ReportMetadata
from ip_sentinel.models.threat_intel import IPIntelResult
from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator
from ip_sentinel.services.investigation_service import InvestigationService

logger = logging.getLogger("ip_sentinel.ui.views.reports")


class ReportsView(QWidget):
    """View interface for configuring and generating HTML/PDF reports."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active_result: Optional[IPIntelResult] = None
        self._setup_ui()

        # Connect to SignalBus to receive current investigation results
        SignalBus.instance().investigation_completed.connect(self._on_investigation_completed)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header Title
        title_label = QLabel("📄 Forensic Report Generation Engine")
        title_label.setStyleSheet("color: #00E5FF; font-size: 20px; font-weight: bold;")
        layout.addWidget(title_label)

        # Active Target Card
        target_card = QFrame()
        target_card.setProperty("class", "cardFrame")
        t_layout = QVBoxLayout(target_card)

        self.target_status_lbl = QLabel("No active investigation selected. Run an investigation first.")
        self.target_status_lbl.setStyleSheet("color: #FBBF24; font-size: 14px; font-weight: bold;")
        t_layout.addWidget(self.target_status_lbl)

        layout.addWidget(target_card)

        # Export Settings Card
        export_card = QFrame()
        export_card.setProperty("class", "cardFrame")
        e_layout = QVBoxLayout(export_card)

        e_title = QLabel("Export Configuration & Output Directory")
        e_title.setProperty("class", "cardHeader")
        e_layout.addWidget(e_title)

        dir_layout = QHBoxLayout()
        self.dir_input = QLineEdit()
        config_dir = ConfigManager().get_settings().export_dir
        self.dir_input.setText(config_dir)

        btn_browse = QPushButton("📁 Browse...")
        btn_browse.setProperty("class", "secondaryButton")
        btn_browse.clicked.connect(self._browse_export_dir)

        dir_layout.addWidget(self.dir_input, 4)
        dir_layout.addWidget(btn_browse, 1)
        e_layout.addLayout(dir_layout)

        layout.addWidget(export_card)

        # Action Buttons Card
        action_card = QFrame()
        action_card.setProperty("class", "cardFrame")
        a_layout = QHBoxLayout(action_card)

        self.btn_html = QPushButton("🌐 Generate HTML Report")
        self.btn_html.setProperty("class", "primaryButton")
        self.btn_html.clicked.connect(lambda: self._generate_report_async("HTML"))

        self.btn_pdf = QPushButton("📕 Generate PDF Report")
        self.btn_pdf.setProperty("class", "primaryButton")
        self.btn_pdf.clicked.connect(lambda: self._generate_report_async("PDF"))

        self.btn_both = QPushButton("📦 Export Both (HTML + PDF)")
        self.btn_both.setProperty("class", "secondaryButton")
        self.btn_both.clicked.connect(lambda: self._generate_report_async("BOTH"))

        a_layout.addWidget(self.btn_html)
        a_layout.addWidget(self.btn_pdf)
        a_layout.addWidget(self.btn_both)

        layout.addWidget(action_card)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        layout.addStretch()

    @Slot(object)
    def _on_investigation_completed(self, result: IPIntelResult):
        self.active_result = result
        self.target_status_lbl.setText(
            f"Active Investigation Target: {result.target_ip} ({result.investigation_id}) | Threat Level: {result.overall_threat_score.level.value}"
        )
        self.target_status_lbl.setStyleSheet("color: #34D399; font-size: 14px; font-weight: bold;")

    def _browse_export_dir(self):
        chosen_dir = QFileDialog.getExistingDirectory(self, "Select Report Export Directory", self.dir_input.text())
        if chosen_dir:
            self.dir_input.setText(chosen_dir)
            ConfigManager().update_settings(export_dir=chosen_dir)

    def _generate_report_async(self, fmt: str):
        if not self.active_result:
            # Fallback auto-run mock investigation if none present
            svc = InvestigationService()
            self.active_result = svc.investigate("185.220.101.5")
            self._on_investigation_completed(self.active_result)

        export_dir = Path(self.dir_input.text().strip())
        export_dir.mkdir(parents=True, exist_ok=True)

        self.progress_bar.setValue(10)
        self.progress_bar.setVisible(True)
        self._set_buttons_enabled(False)

        signals = TaskPool.execute(self._render_report_task, fmt, export_dir, self.active_result)
        signals.progress.connect(self.progress_bar.setValue)
        signals.result.connect(self._on_report_success)
        signals.error.connect(self._on_report_error)
        signals.finished.connect(lambda: self._set_buttons_enabled(True))

    def _set_buttons_enabled(self, enabled: bool):
        self.btn_html.setEnabled(enabled)
        self.btn_pdf.setEnabled(enabled)
        self.btn_both.setEnabled(enabled)

    def _render_report_task(
        self,
        fmt: str,
        export_dir: Path,
        result: IPIntelResult,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> str:
        if progress_callback:
            progress_callback(30, "Generating forensic report data...")

        data = ReportData(
            result=result,
            metadata=ReportMetadata(),
        )
        base_name = f"Report_{result.target_ip.replace('.', '_').replace(':', '_')}_{result.investigation_id}"
        created_paths = []

        if fmt in ("HTML", "BOTH"):
            if progress_callback:
                progress_callback(50, "Rendering Jinja2 HTML report...")
            html_path = export_dir / f"{base_name}.html"
            HTMLReportGenerator().generate_report(data, html_path)
            created_paths.append(str(html_path))

        if fmt in ("PDF", "BOTH"):
            if progress_callback:
                progress_callback(80, "Rendering ReportLab PDF report...")
            pdf_path = export_dir / f"{base_name}.pdf"
            PDFReportGenerator().generate_report(data, pdf_path)
            created_paths.append(str(pdf_path))

        if progress_callback:
            progress_callback(100, "Report export complete.")

        return "\n".join(created_paths)

    @Slot(str)
    def _on_report_success(self, paths_str: str):
        self.progress_bar.setValue(100)
        self.progress_bar.setVisible(False)
        QMessageBox.information(
            self,
            "Report Generation Successful",
            f"Forensic report generated successfully:\n\n{paths_str}",
        )

    @Slot(tuple)
    def _on_report_error(self, err_tuple: Tuple):
        self.progress_bar.setVisible(False)
        exctype, val, tb = err_tuple
        logger.error(f"Report generation error: {val}")
        QMessageBox.critical(self, "Report Error", f"Failed to generate report: {val}")
