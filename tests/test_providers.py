"""Unit tests for MockIntelProvider and provider interface."""

from ip_sentinel.models.threat_intel import DataStatus, ThreatLevel
from ip_sentinel.providers.mock_provider import MockIntelProvider


def test_mock_provider_contract():
    prov = MockIntelProvider()
    assert prov.provider_name == "mock"
    assert prov.is_configured() is True
    assert prov.health_check() is True


def test_mock_provider_clean_scenario():
    prov = MockIntelProvider()
    res = prov.query_ip("1.1.1.1")
    
    assert res.status == DataStatus.AVAILABLE
    assert res.threat_score is not None
    assert res.threat_score.level == ThreatLevel.CLEAN
    assert res.threat_score.score == 0


def test_mock_provider_suspicious_scenario():
    prov = MockIntelProvider()
    res = prov.query_ip("198.51.100.45")
    
    assert res.status == DataStatus.AVAILABLE
    assert res.threat_score is not None
    assert res.threat_score.level == ThreatLevel.SUSPICIOUS
    assert 40 <= res.threat_score.score <= 75


def test_mock_provider_malicious_scenario():
    prov = MockIntelProvider()
    res = prov.query_ip("185.220.101.5")
    
    assert res.status == DataStatus.AVAILABLE
    assert res.threat_score is not None
    assert res.threat_score.level == ThreatLevel.MALICIOUS
    assert res.threat_score.score >= 90
    assert len(res.evidence) > 0
