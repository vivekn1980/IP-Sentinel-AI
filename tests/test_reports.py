"""Unit tests for HTML and PDF Forensic Report Generators."""

from pathlib import Path
from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator


def test_html_report_generation(sample_report_data, tmp_path):
    out_file = tmp_path / "test_report.html"
    generator = HTMLReportGenerator()
    result_path = generator.generate_report(sample_report_data, out_file)

    assert result_path.exists()
    assert result_path.stat().st_size > 0

    content = result_path.read_text(encoding="utf-8")
    assert sample_report_data.result.target_ip in content
    assert sample_report_data.result.investigation_id in content
    assert str(sample_report_data.result.overall_threat_score.score) in content
    assert "DEMO / MOCK DATA" in content
    assert "Network Geolocation" in content
    assert "Structured Threat Telemetry Evidence" in content


def test_pdf_report_generation(sample_report_data, tmp_path):
    out_file = tmp_path / "test_report.pdf"
    generator = PDFReportGenerator()
    result_path = generator.generate_report(sample_report_data, out_file)

    assert result_path.exists()
    assert result_path.stat().st_size > 0

    # Verify standard PDF magic header bytes %PDF-
    with open(result_path, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"
