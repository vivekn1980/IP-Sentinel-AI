"""Unit tests verifying Phase 2 report generation with RDAP, GeoIP, ASN, DNS, and disclaimers."""

from ip_sentinel.models.report_model import ReportData, ReportMetadata
from ip_sentinel.models.threat_intel import ASNData, DNSData, DataStatus, GeoIPData, IPIntelResult, RDAPData
from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator


def test_phase2_html_and_pdf_reports(tmp_path):
    rdap = RDAPData(status=DataStatus.AVAILABLE, network_name="TEST-NET", organization="Test Org")
    asn = ASNData(status=DataStatus.AVAILABLE, asn=65000, asn_org="Test ASN Org")
    geo = GeoIPData(status=DataStatus.AVAILABLE, country_name="Germany", country_code="DE", city="Berlin")
    dns = DNSData(status=DataStatus.AVAILABLE, hostname="test.example.com")

    res = IPIntelResult(
        investigation_id="INV-TEST1234",
        target_ip="198.51.100.1",
        timestamp="2026-09-13 12:00:00 UTC",
        rdap=rdap,
        asn_data=asn,
        geoip=geo,
        dns=dns,
    )

    data = ReportData(result=res, metadata=ReportMetadata())

    html_file = tmp_path / "phase2_report.html"
    pdf_file = tmp_path / "phase2_report.pdf"

    HTMLReportGenerator().generate_report(data, html_file)
    PDFReportGenerator().generate_report(data, pdf_file)

    assert html_file.exists() and html_file.stat().st_size > 0
    assert pdf_file.exists() and pdf_file.stat().st_size > 0

    html_content = html_file.read_text(encoding="utf-8")
    assert "Registration Data Access Protocol (RDAP)" in html_content
    assert "GeoIP information represents approximate network geolocation" in html_content
    assert "198.51.100.1" in html_content
    assert "TEST-NET" in html_content
    assert "Germany" in html_content

    with open(pdf_file, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"
