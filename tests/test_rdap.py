"""Unit tests for RDAPProvider using mocked HTTP responses."""

from unittest.mock import MagicMock, patch
import requests
from ip_sentinel.models.threat_intel import DataStatus
from ip_sentinel.providers.rdap_provider import RDAPProvider


@patch("requests.get")
def test_rdap_success(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "name": "CLOUDFLARE-NET",
        "startAddress": "1.1.1.0",
        "endAddress": "1.1.1.255",
        "country": "US",
        "port43": "whois.arin.net",
        "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.com"]]],
            },
        ],
    }
    mock_get.return_value = mock_resp

    prov = RDAPProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    res = prov.query_rdap("1.1.1.1")
    assert res.status == DataStatus.AVAILABLE
    assert res.network_name == "CLOUDFLARE-NET"
    assert res.organization == "Cloudflare, Inc."
    assert res.abuse_contact == "abuse@cloudflare.com"
    assert res.registry == "ARIN"
    assert res.cidr == "1.1.1.0/24"


@patch("requests.get")
def test_rdap_timeout(mock_get, tmp_path):
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    prov = RDAPProvider(timeout=1.0, cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    res = prov.query_rdap("8.8.8.8")
    assert res.status == DataStatus.ERROR
    assert "timed out" in res.error_message.lower()


@patch("requests.get")
def test_rdap_rate_limit(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    prov = RDAPProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    res = prov.query_rdap("8.8.8.8")
    assert res.status == DataStatus.ERROR
    assert "429" in res.error_message


@patch("requests.get")
def test_rdap_not_found(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    prov = RDAPProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path

    res = prov.query_rdap("192.0.2.1")
    assert res.status == DataStatus.UNAVAILABLE
    assert "404" in res.error_message
