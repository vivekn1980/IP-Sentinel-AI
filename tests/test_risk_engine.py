"""Unit tests for RiskEngine."""

from ip_sentinel.models.threat_intel import (
    ASNData,
    DataStatus,
    EvidenceItem,
    EvidenceSummary,
    ProviderResult,
    RDAPData,
    ThreatLevel,
    ThreatScore,
)
from ip_sentinel.services.risk_engine import RiskEngine


def test_risk_engine_clean_ip():
    engine = RiskEngine()
    summary = EvidenceSummary(total_count=3, info_count=3)
    ev_list = [
        EvidenceItem(source="RDAP", category="NETWORK", severity="INFO", confidence=90, observation="Clean IP")
    ]
    p_res = {
        "mock": ProviderResult(
            provider_name="mock",
            status=DataStatus.AVAILABLE,
            threat_score=ThreatScore(score=0, level=ThreatLevel.VERY_LOW),
        )
    }

    score = engine.evaluate_risk(
        evidence_list=ev_list,
        evidence_summary=summary,
        provider_results=p_res,
        rdap=RDAPData(),
        asn_data=ASNData(),
    )

    assert score.score < 15
    assert score.level == ThreatLevel.VERY_LOW


def test_risk_engine_malicious_ip():
    engine = RiskEngine()
    summary = EvidenceSummary(total_count=5, critical_count=2, high_count=1)
    ev_list = [
        EvidenceItem(source="AbuseIPDB", category="REPUTATION", severity="CRITICAL", confidence=95, observation="Malicious IP")
    ]
    p_res = {
        "abuseipdb": ProviderResult(
            provider_name="abuseipdb",
            status=DataStatus.AVAILABLE,
            threat_score=ThreatScore(score=96, level=ThreatLevel.CRITICAL),
        )
    }

    score = engine.evaluate_risk(
        evidence_list=ev_list,
        evidence_summary=summary,
        provider_results=p_res,
        rdap=RDAPData(),
        asn_data=ASNData(),
    )

    assert score.score >= 85
    assert score.level == ThreatLevel.CRITICAL
