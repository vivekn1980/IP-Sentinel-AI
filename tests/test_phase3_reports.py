"""Unit tests verifying Phase 3 report rendering with evidence summaries, risk assessment, and threat feeds."""

from ip_sentinel.models.report_model import ReportData, ReportMetadata
from ip_sentinel.models.threat_intel import (
    ASNData,
    DNSData,
    DataStatus,
    EvidenceItem,
    EvidenceSummary,
    GeoIPData,
    IPIntelResult,
    ProviderResult,
    RDAPData,
    ReputationData,
    ThreatLevel,
    ThreatScore,
)
from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator


def test_phase3_html_and_pdf_reports(tmp_path):
    rdap = RDAPData(status=DataStatus.AVAILABLE, network_name="PHASE3-NET", organization="Phase3 Corp")
    asn = ASNData(status=DataStatus.AVAILABLE, asn=3333, asn_org="Phase3 ASN")
    geo = GeoIPData(status=DataStatus.AVAILABLE, country_name="United States", country_code="US")
    dns = DNSData(status=DataStatus.AVAILABLE, hostname="node.phase3.com")

    p1 = ProviderResult(
        provider_name="abuseipdb",
        status=DataStatus.AVAILABLE,
        threat_score=ThreatScore(score=85, level=ThreatLevel.HIGH),
        reputation=ReputationData(provider_name="abuseipdb", abuse_score=85, total_reports=45, distinct_reporters=12),
        evidence=[
            EvidenceItem(
                source="AbuseIPDB",
                category="REPUTATION",
                severity="HIGH",
                confidence=90,
                observation="Abuse reports filed for web attacks.",
            )
        ],
    )

    ev_summary = EvidenceSummary(total_count=1, high_count=1)

    res = IPIntelResult(
        investigation_id="INV-PHASE3-99",
        target_ip="198.51.100.99",
        timestamp="2026-09-13 14:00:00 UTC",
        overall_threat_score=ThreatScore(score=85, level=ThreatLevel.HIGH, confidence=95),
        rdap=rdap,
        asn_data=asn,
        geoip=geo,
        dns=dns,
        provider_results={"abuseipdb": p1},
        aggregated_evidence=p1.evidence,
        evidence_summary=ev_summary,
        has_conflicting_evidence=True,
        conflict_explanation="Sample conflict note for report test",
    )

    data = ReportData(result=res, metadata=ReportMetadata())

    html_file = tmp_path / "phase3_report.html"
    pdf_file = tmp_path / "phase3_report.pdf"

    HTMLReportGenerator().generate_report(data, html_file)
    PDFReportGenerator().generate_report(data, pdf_file)

    assert html_file.exists() and html_file.stat().st_size > 0
    assert pdf_file.exists() and pdf_file.stat().st_size > 0

    html_content = html_file.read_text(encoding="utf-8")
    assert "Passive Threat Intelligence Feeds" in html_content
    assert "Aggregated Evidence Summary" in html_content
    assert "abuseipdb" in html_content
    assert "Sample conflict note for report test" in html_content

    with open(pdf_file, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"
