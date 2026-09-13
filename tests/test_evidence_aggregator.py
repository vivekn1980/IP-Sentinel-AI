"""Unit tests for EvidenceAggregator."""

from ip_sentinel.models.threat_intel import (
    ASNData,
    DNSData,
    DataStatus,
    EvidenceItem,
    GeoIPData,
    ProviderResult,
    RDAPData,
    ThreatLevel,
    ThreatScore,
    WAFContext,
)
from ip_sentinel.services.evidence_aggregator import EvidenceAggregator


def test_evidence_aggregation_and_deduplication():
    rdap = RDAPData(status=DataStatus.AVAILABLE, network_name="NET-TEST", organization="Org Test")
    asn = ASNData(status=DataStatus.AVAILABLE, asn=12345, asn_org="ASN Org")
    geo = GeoIPData(status=DataStatus.AVAILABLE, country_name="US", country_code="US")
    dns = DNSData(status=DataStatus.AVAILABLE, hostname="test.domain.com")

    waf = WAFContext(request_count=50, rule_triggered="942100 SQL Injection", uri="/login")

    mock_prov = ProviderResult(
        provider_name="mock",
        status=DataStatus.AVAILABLE,
        evidence=[
            EvidenceItem(
                source="Mock Feed",
                category="THREAT_INTELLIGENCE",
                severity="HIGH",
                confidence=90,
                observation="SQL Injection attack observed.",
            )
        ],
    )

    agg = EvidenceAggregator()
    evidence_list, summary, has_conflict, notes = agg.aggregate_evidence(
        rdap=rdap,
        asn_data=asn,
        geoip=geo,
        dns=dns,
        provider_results={"mock": mock_prov},
        waf_context=waf,
    )

    assert summary.total_count >= 5
    assert summary.high_count >= 1
    assert any(e.category == "WAF" for e in evidence_list)
    assert any(e.category == "NETWORK" for e in evidence_list)


def test_contradictory_evidence_detection():
    rdap = RDAPData(status=DataStatus.AVAILABLE, organization="Amazon.com, Inc.")
    asn = ASNData(status=DataStatus.AVAILABLE, asn=16509, asn_org="Amazon.com, Inc.")

    p1 = ProviderResult(
        provider_name="abuseipdb",
        status=DataStatus.AVAILABLE,
        threat_score=ThreatScore(score=95, level=ThreatLevel.CRITICAL),
    )
    p2 = ProviderResult(
        provider_name="virustotal",
        status=DataStatus.AVAILABLE,
        threat_score=ThreatScore(score=0, level=ThreatLevel.VERY_LOW),
    )

    agg = EvidenceAggregator()
    evidence_list, summary, has_conflict, notes = agg.aggregate_evidence(
        rdap=rdap,
        asn_data=asn,
        geoip=GeoIPData(),
        dns=DNSData(),
        provider_results={"abuseipdb": p1, "virustotal": p2},
    )

    assert has_conflict is True
    assert "Contradictory" in notes
