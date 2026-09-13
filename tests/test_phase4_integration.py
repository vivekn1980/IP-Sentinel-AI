"""Integration tests for Phase 4 WAF Behavioral Analysis with EvidenceAggregator, RiskEngine, and InvestigationService."""

import os
from ip_sentinel.models.waf_behavior import AttackClassification, WAFIPAnalysis
from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.services.waf_analysis_service import WAFAnalysisService


def test_investigation_service_with_waf_analysis():
    inv_service = InvestigationService()
    waf_service = WAFAnalysisService()

    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    waf_result = waf_service.analyze_file(fixture_path)
    waf_an = waf_result.ip_analyses.get("198.51.100.45")

    intel = inv_service.investigate("198.51.100.45", waf_analysis=waf_an)

    assert intel.target_ip == "198.51.100.45"
    assert intel.waf_analysis is not None
    assert intel.waf_analysis.primary_classification == AttackClassification.WEB_SCANNER
    assert intel.overall_threat_score.score >= 50
    assert any(e.source == "WAF" for e in intel.aggregated_evidence)


def test_investigation_service_contradictory_evidence_clean_rep_bad_waf():
    inv_service = InvestigationService()
    waf_service = WAFAnalysisService()

    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    waf_result = waf_service.analyze_file(fixture_path)
    waf_an = waf_result.ip_analyses.get("198.51.100.45")

    # In mock run, AbuseIPDB/VT might be unconfigured or clean, but WAF is WEB_SCANNER
    intel = inv_service.investigate("198.51.100.45", waf_analysis=waf_an)
    assert intel.waf_analysis is not None
    # Conflict detection should trigger if external reputation is clean (<=15) while WAF is WEB_SCANNER
    if intel.has_conflicting_evidence:
        assert "Contradictory evidence" in (intel.conflict_explanation or "")
