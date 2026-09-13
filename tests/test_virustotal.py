"""Unit tests for VirusTotalProvider using mocked HTTP responses."""

from unittest.mock import MagicMock, patch
import requests
from ip_sentinel.models.threat_intel import DataStatus, ThreatLevel
from ip_sentinel.providers.virustotal_provider import VirusTotalProvider


def test_virustotal_unconfigured():
    prov = VirusTotalProvider()
    with patch.object(prov, "is_configured", return_value=False):
        res = prov.query_ip("1.1.1.1")
        assert res.status == DataStatus.NOT_CONFIGURED


@patch("requests.get")
def test_virustotal_success(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 15,
                },
                "reputation": 45,
                "tags": ["malware", "c2"],
            }
        }
    }
    mock_get.return_value = mock_resp

    prov = VirusTotalProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path
    with patch.object(prov, "is_configured", return_value=True), patch.object(prov, "_get_api_key", return_value="vt_mock_key"):
        res = prov.query_ip("185.220.101.5")
        assert res.status == DataStatus.AVAILABLE
        assert res.threat_score.level == ThreatLevel.CRITICAL
        assert res.reputation.malicious_count == 8
        assert len(res.evidence) > 0


@patch("requests.get")
def test_virustotal_clean_ip(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 5,
                },
                "reputation": 0,
                "tags": ["trusted"],
            }
        }
    }
    mock_get.return_value = mock_resp

    prov = VirusTotalProvider(cache_ttl=0)
    prov.cache.cache_dir = tmp_path
    with patch.object(prov, "is_configured", return_value=True), patch.object(prov, "_get_api_key", return_value="vt_mock_key"):
        res = prov.query_ip("1.1.1.1")
        assert res.status == DataStatus.AVAILABLE
        assert res.threat_score.score == 0
        assert res.threat_score.level == ThreatLevel.VERY_LOW
