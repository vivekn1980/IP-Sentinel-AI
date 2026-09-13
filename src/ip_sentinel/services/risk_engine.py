"""Risk Engine evaluating evidence-backed threat scores and classification levels."""

import logging
from typing import Dict, List, Optional

from ip_sentinel.models.threat_intel import (
    ASNData,
    DNSData,
    DataStatus,
    EvidenceItem,
    EvidenceSummary,
    GeoIPData,
    ProviderResult,
    RDAPData,
    ThreatLevel,
    ThreatScore,
    WAFContext,
)

logger = logging.getLogger("ip_sentinel.services.risk_engine")


class RiskEngine:
    """Evaluates multi-source evidence to calculate normalized threat scores (0-100) and threat levels."""

    def evaluate_risk(
        self,
        evidence_list: List[EvidenceItem],
        evidence_summary: EvidenceSummary,
        provider_results: Dict[str, ProviderResult],
        rdap: RDAPData,
        asn_data: ASNData,
        waf_context: Optional[WAFContext] = None,
        has_conflicting_evidence: bool = False,
        conflict_explanation: Optional[str] = None,
    ) -> ThreatScore:
        """Calculate weighted threat score based on evidence telemetry.
        
        Returns:
            Normalized ThreatScore object.
        """
        raw_score = 0
        total_weight = 0

        # 1. Evaluate Evidence Severity Points
        crit_pts = evidence_summary.critical_count * 40
        high_pts = evidence_summary.high_count * 25
        med_pts = evidence_summary.medium_count * 10
        low_pts = evidence_summary.low_count * 3

        evidence_score = min(100, crit_pts + high_pts + med_pts + low_pts)

        # 2. Evaluate Threat Provider Scores
        provider_scores = []
        for p_name, res in provider_results.items():
            if res.status == DataStatus.AVAILABLE and res.threat_score:
                provider_scores.append(res.threat_score.score)

        if provider_scores and evidence_score > 0:
            avg_prov_score = sum(provider_scores) / len(provider_scores)
            final_score_val = int((evidence_score * 0.6) + (avg_prov_score * 0.4))
        elif provider_scores:
            final_score_val = int(sum(provider_scores) / len(provider_scores))
        else:
            final_score_val = evidence_score

        # Cap score at 100
        final_score_val = min(100, max(0, final_score_val))

        # 3. Assign Threat Level
        if final_score_val >= 85:
            level = ThreatLevel.CRITICAL
        elif final_score_val >= 65:
            level = ThreatLevel.HIGH
        elif final_score_val >= 40:
            level = ThreatLevel.MEDIUM
        elif final_score_val >= 15:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.VERY_LOW

        # 4. Calculate Confidence Percentage
        confidence = 70
        configured_providers = sum(1 for p in provider_results.values() if p.status == DataStatus.AVAILABLE)
        if configured_providers >= 2:
            confidence += 20
        elif configured_providers == 1:
            confidence += 10

        if has_conflicting_evidence:
            confidence = max(50, confidence - 15)

        return ThreatScore(
            score=final_score_val,
            level=level,
            confidence=min(100, confidence),
            status=DataStatus.AVAILABLE,
            conflicting_evidence=has_conflicting_evidence,
            conflict_notes=conflict_explanation,
        )
