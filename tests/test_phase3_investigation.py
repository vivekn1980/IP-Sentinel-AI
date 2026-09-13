"""Unit tests for Phase 3 InvestigationService with WAFContext and threat adapters."""

from unittest.mock import patch
from ip_sentinel.models.threat_intel import DataStatus, RDAPData, ThreatLevel, WAFContext
from ip_sentinel.services.investigation_service import InvestigationService


@patch("ip_sentinel.providers.rdap_provider.RDAPProvider.query_rdap")
@patch("ip_sentinel.providers.geoip_provider.GeoIPProvider.query_geoip_and_asn")
def test_phase3_investigation_with_waf(mock_geo, mock_rdap):
    mock_rdap.return_value = RDAPData(
        status=DataStatus.AVAILABLE,
        ip_address="198.51.100.45",
        network_name="TEST-WAF-NET",
        organization="Test Target Org",
    )

    waf = WAFContext(
        request_count=120,
        time_window="5m",
        rule_triggered="942100 SQL Injection",
        uri="/api/v1/checkout",
    )

    svc = InvestigationService()
    res = svc.investigate("198.51.100.45", waf_context=waf)

    assert res.target_ip == "198.51.100.45"
    assert res.waf_context is not None
    assert res.waf_context.request_count == 120
    assert any(e.category == "WAF" for e in res.aggregated_evidence)
    assert res.evidence_summary.total_count > 0
