"""Integration unit tests for Phase 2 InvestigationService resilience and provider aggregation."""

from unittest.mock import patch
from ip_sentinel.models.threat_intel import DataStatus, GeoIPData, RDAPData, ThreatLevel
from ip_sentinel.services.investigation_service import InvestigationService


@patch("ip_sentinel.providers.rdap_provider.RDAPProvider.query_rdap")
@patch("ip_sentinel.providers.geoip_provider.GeoIPProvider.query_geoip_and_asn")
def test_phase2_investigation_partial_failure(mock_geo, mock_rdap):
    # Mock RDAP success
    mock_rdap.return_value = RDAPData(
        status=DataStatus.AVAILABLE,
        ip_address="185.220.101.5",
        network_name="TOR-EXIT-NET",
        organization="Tor Exit Operators",
    )
    # Mock GeoIP failure (Exception)
    mock_geo.side_effect = RuntimeError("GeoIP service network error")

    svc = InvestigationService()
    res = svc.investigate("185.220.101.5")

    # Verify overall investigation completed cleanly despite GeoIP failure
    assert res.target_ip == "185.220.101.5"
    assert res.rdap_status == DataStatus.AVAILABLE
    assert res.rdap.network_name == "TOR-EXIT-NET"
    assert res.geoip_status == DataStatus.ERROR
    assert "GeoIP Error" in res.geoip.error_message
