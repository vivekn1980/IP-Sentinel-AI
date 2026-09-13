"""Unit tests for GeoIPProvider using mocked HTTP responses."""

from unittest.mock import MagicMock, patch
import requests
from ip_sentinel.models.threat_intel import DataStatus
from ip_sentinel.providers.geoip_provider import MANDATORY_GEOIP_DISCLAIMER, GeoIPProvider


@patch("requests.get")
def test_geoip_success(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "city": "Ashburn",
        "timezone": "America/New_York",
        "isp": "Cloudflare, Inc.",
        "org": "Cloudflare, Inc.",
        "as": "AS13335 Cloudflare, Inc.",
        "lat": 39.0437,
        "lon": -77.4875,
    }
    mock_get.return_value = mock_resp

    prov = GeoIPProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    geo, asn = prov.query_geoip_and_asn("1.1.1.1")

    assert geo.status == DataStatus.AVAILABLE
    assert geo.country_name == "United States"
    assert geo.country_code == "US"
    assert geo.city == "Ashburn"
    assert geo.disclaimer == MANDATORY_GEOIP_DISCLAIMER

    assert asn.status == DataStatus.AVAILABLE
    assert asn.asn == 13335
    assert asn.asn_org == "Cloudflare, Inc."


@patch("requests.get")
def test_geoip_failure(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_get.return_value = mock_resp

    prov = GeoIPProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    geo, asn = prov.query_geoip_and_asn("185.220.101.5")
    assert geo.status == DataStatus.UNAVAILABLE
    assert geo.disclaimer == MANDATORY_GEOIP_DISCLAIMER
    assert asn.status == DataStatus.UNAVAILABLE
