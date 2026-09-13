"""Unit tests for AbuseIPDBProvider using mocked HTTP responses."""

from unittest.mock import MagicMock, patch
import requests
from ip_sentinel.models.threat_intel import DataStatus, ThreatLevel
from ip_sentinel.providers.abuseipdb_provider import AbuseIPDBProvider


def test_abuseipdb_unconfigured():
    prov = AbuseIPDBProvider()
    with patch.object(prov, "is_configured", return_value=False):
        res = prov.query_ip("1.1.1.1")
        assert res.status == DataStatus.NOT_CONFIGURED


@patch("requests.get")
def test_abuseipdb_success(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "185.220.101.5",
            "abuseConfidenceScore": 100,
            "totalReports": 150,
            "numDistinctUsers": 42,
            "domain": "tor-exit.example.org",
            "isp": "Tor Exit Network",
            "usageType": "Data Center/Web Hosting/Transit",
            "lastReportedAt": "2026-09-13T10:00:00+00:00",
            "reports": [{"categories": [18, 21]}],
        }
    }
    mock_get.return_value = mock_resp

    prov = AbuseIPDBProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path
    with patch.object(prov, "is_configured", return_value=True), patch.object(prov, "_get_api_key", return_value="mock_key"):
        res = prov.query_ip("185.220.101.5")
        assert res.status == DataStatus.AVAILABLE
        assert res.threat_score.score == 100
        assert res.threat_score.level == ThreatLevel.CRITICAL
        assert res.reputation.total_reports == 150
        assert "Brute-Force" in res.reputation.categories


@patch("requests.get")
def test_abuseipdb_invalid_key(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    prov = AbuseIPDBProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path
    with patch.object(prov, "is_configured", return_value=True), patch.object(prov, "_get_api_key", return_value="invalid_key"):
        res = prov.query_ip("185.220.101.5")
        assert res.status == DataStatus.ERROR
        assert "Invalid" in res.error_message


@patch("requests.get")
def test_abuseipdb_rate_limit(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    prov = AbuseIPDBProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path
    with patch.object(prov, "is_configured", return_value=True), patch.object(prov, "_get_api_key", return_value="mock_key"):
        res = prov.query_ip("185.220.101.5")
        assert res.status == DataStatus.RATE_LIMITED
        assert "429" in res.error_message
