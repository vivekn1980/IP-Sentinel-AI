"""Evidence Aggregator normalizing, deduplicating, and correlating multi-source intelligence."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from ip_sentinel.models.threat_intel import (
    ASNData,
    DNSData,
    DataStatus,
    EvidenceItem,
    EvidenceSummary,
    GeoIPData,
    ProviderResult,
    RDAPData,
    WAFContext,
)

logger = logging.getLogger("ip_sentinel.services.evidence_aggregator")


class EvidenceAggregator:
    """Aggregates, normalizes, and correlates evidence items from network, DNS, WAF, and threat sources."""

    def aggregate_evidence(
        self,
        rdap: RDAPData,
        asn_data: ASNData,
        geoip: GeoIPData,
        dns: DNSData,
        provider_results: Dict[str, ProviderResult],
        waf_context: Optional[WAFContext] = None,
        waf_analysis: Optional[Any] = None,
    ) -> Tuple[List[EvidenceItem], EvidenceSummary, bool, Optional[str]]:
        """Collect, deduplicate, and analyze all investigation telemetry into normalized evidence.
        
        Returns:
            Tuple of (evidence_list, evidence_summary, has_conflicting_evidence, conflict_explanation)
        """
        raw_evidence: List[EvidenceItem] = []

        # 1. Collect evidence from RDAP & Network
        if rdap.status == DataStatus.AVAILABLE and rdap.organization:
            raw_evidence.append(
                EvidenceItem(
                    source="RDAP",
                    category="NETWORK",
                    severity="INFO",
                    confidence=95,
                    observation=f"Allocated Network: '{rdap.network_name or 'N/A'}' ({rdap.cidr or 'N/A'}) registered to '{rdap.organization}' via {rdap.registry or 'RIR'}.",
                )
            )

        # 2. Collect evidence from ASN
        if asn_data.status == DataStatus.AVAILABLE and asn_data.asn:
            raw_evidence.append(
                EvidenceItem(
                    source="ASN Telemetry",
                    category="ASN",
                    severity="INFO",
                    confidence=90,
                    observation=f"Autonomous System AS{asn_data.asn} ({asn_data.asn_org or 'N/A'}) routing prefix {asn_data.network_prefix or 'N/A'}.",
                )
            )

        # 3. Collect evidence from Geolocation
        if geoip.status == DataStatus.AVAILABLE and geoip.country_name:
            raw_evidence.append(
                EvidenceItem(
                    source="GeoIP Engine",
                    category="GEOLOCATION",
                    severity="INFO",
                    confidence=80,
                    observation=f"Network registered in {geoip.country_name} ({geoip.country_code}) - Region: {geoip.region or 'N/A'}, City: {geoip.city or 'N/A'}.",
                )
            )

        # 4. Collect evidence from DNS
        if dns.status == DataStatus.AVAILABLE and dns.hostname:
            raw_evidence.append(
                EvidenceItem(
                    source="DNS Telemetry",
                    category="DNS",
                    severity="INFO",
                    confidence=85,
                    observation=f"Reverse PTR hostname resolved: {dns.hostname}.",
                )
            )

        # 5. Collect WAF Context Evidence if provided
        if waf_context and waf_context.request_count > 0:
            sev = "HIGH" if waf_context.request_count >= 100 else ("MEDIUM" if waf_context.request_count >= 20 else "LOW")
            rule_str = f" Rule Triggered: '{waf_context.rule_triggered}'." if waf_context.rule_triggered else ""
            raw_evidence.append(
                EvidenceItem(
                    source="WAF Rule Engine",
                    category="WAF",
                    severity=sev,
                    confidence=95,
                    observation=f"Blocked {waf_context.request_count} requests in {waf_context.time_window}.{rule_str} Target URI: {waf_context.uri or 'N/A'}.",
                    supporting_data={
                        "rule": waf_context.rule_triggered,
                        "uri": waf_context.uri,
                        "user_agent": waf_context.user_agent,
                    },
                )
            )

        # 5b. Collect WAF Behavioral Analysis Evidence if provided
        if waf_analysis and hasattr(waf_analysis, "evidence_items") and waf_analysis.evidence_items:
            raw_evidence.extend(waf_analysis.evidence_items)

        # 6. Collect evidence from Intelligence Providers
        for p_name, res in provider_results.items():
            if res.status == DataStatus.AVAILABLE and res.evidence:
                raw_evidence.extend(res.evidence)

        # Deduplicate evidence items based on observation text
        seen_observations = set()
        deduped_evidence: List[EvidenceItem] = []
        for item in raw_evidence:
            obs_key = item.observation.strip().lower()
            if obs_key not in seen_observations:
                seen_observations.add(obs_key)
                deduped_evidence.append(item)

        # Calculate Evidence Summary counts
        crit = sum(1 for e in deduped_evidence if e.severity == "CRITICAL")
        high = sum(1 for e in deduped_evidence if e.severity == "HIGH")
        med = sum(1 for e in deduped_evidence if e.severity == "MEDIUM")
        low = sum(1 for e in deduped_evidence if e.severity == "LOW")
        info = sum(1 for e in deduped_evidence if e.severity == "INFO")

        summary = EvidenceSummary(
            total_count=len(deduped_evidence),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
        )

        # Detect Contradictory Evidence
        has_conflict = False
        conflict_notes: Optional[str] = None

        abuse_score = provider_results.get("abuseipdb", {}).threat_score.score if "abuseipdb" in provider_results and provider_results["abuseipdb"].threat_score else None
        vt_score = provider_results.get("virustotal", {}).threat_score.score if "virustotal" in provider_results and provider_results["virustotal"].threat_score else None

        if abuse_score is not None and vt_score is not None:
            if abs(abuse_score - vt_score) >= 40:
                has_conflict = True
                conflict_notes = f"Contradictory intelligence detected: AbuseIPDB score is {abuse_score}/100 while VirusTotal score is {vt_score}/100."
        
        # Check WAF behavior vs reputation conflict
        if waf_analysis and hasattr(waf_analysis, "primary_classification"):
            cls_name = waf_analysis.primary_classification.value if hasattr(waf_analysis.primary_classification, "value") else str(waf_analysis.primary_classification)
            max_rep_score = max([s for s in [abuse_score, vt_score] if s is not None], default=0)
            if max_rep_score <= 15 and cls_name in ("WEB_SCANNER", "CREDENTIAL_ATTACK", "HTTP_FLOOD", "MALICIOUS_BOT"):
                has_conflict = True
                conflict_notes = (
                    f"Contradictory evidence: Target IP has clean external reputation (score <= 15), "
                    f"but active WAF telemetry exhibits malicious behavioral pattern ('{cls_name}')."
                )
            elif max_rep_score >= 70 and cls_name == "NORMAL_CLIENT":
                has_conflict = True
                conflict_notes = (
                    f"Contradictory evidence: Target IP has high external threat reputation (score {max_rep_score}/100), "
                    f"but current WAF telemetry shows normal client behavior."
                )

        # Check cloud/datacenter vs abuse report conflict
        org_lower = (rdap.organization or asn_data.asn_org or "").lower()
        is_datacenter = any(kw in org_lower for kw in ["amazon", "aws", "google", "cloudflare", "hetzner", "digitalocean", "linode", "ovh"])
        if is_datacenter and (crit == 0 and high == 0 and (abuse_score or 0) < 20) and not has_conflict:
            has_conflict = True
            conflict_notes = (
                f"Note: IP belongs to cloud/datacenter infrastructure ({rdap.organization or asn_data.asn_org}), "
                "but zero active malicious indicators or abuse reports were observed."
            )

        return deduped_evidence, summary, has_conflict, conflict_notes
