"""Integration tests for Phase 4 HTML and PDF report generation containing WAF behavioral analysis."""

import os
import pytest

from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator
from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.services.waf_analysis_service import WAFAnalysisService


def test_phase4_html_and_pdf_reports(tmp_path):
    inv_service = InvestigationService()
    waf_service = WAFAnalysisService()

    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    waf_result = waf_service.analyze_file(fixture_path)
    waf_an = waf_result.ip_analyses.get("198.51.100.45")

    from ip_sentinel.models.report_model import ReportData, ReportMetadata

    result = inv_service.investigate("198.51.100.45", waf_analysis=waf_an)
    report_data = ReportData(result=result, metadata=ReportMetadata())

    # HTML Report
    html_gen = HTMLReportGenerator()
    html_path = os.path.join(tmp_path, "phase4_report.html")
    res_html = html_gen.generate_report(report_data, html_path)
    assert os.path.exists(res_html)

    with open(res_html, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert "WAF Behavioral &amp; Attack Analysis" in html_content or "WAF Behavioral & Attack Analysis" in html_content
    assert "WEB_SCANNER" in html_content
    assert "Mandatory Behavioral Disclaimer" in html_content

    # PDF Report
    pdf_gen = PDFReportGenerator()
    pdf_path = os.path.join(tmp_path, "phase4_report.pdf")
    res_pdf = pdf_gen.generate_report(report_data, pdf_path)
    assert os.path.exists(res_pdf)
    assert os.path.getsize(res_pdf) > 1000
