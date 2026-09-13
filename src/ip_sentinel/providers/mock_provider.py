"""Deterministic Mock Threat Intelligence Provider for offline testing & UI verification.

Zero external Internet access. Supports three scenarios: CLEAN, SUSPICIOUS, MALICIOUS.
"""

import time
from typing import List

from ip_sentinel.models.threat_intel import (
    DataStatus,
    EvidenceItem,
    ProviderResult,
    ReputationData,
    ThreatLevel,
    ThreatScore,
)
from ip_sentinel.providers.base import BaseIntelProvider


class MockIntelProvider(BaseIntelProvider):
    """Deterministic threat intelligence provider producing structured mock evidence."""

    @property
    def provider_name(self) -> str:
        return "mock"

    def is_configured(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True

    def query_ip(self, target_ip: str) -> ProviderResult:
        """Return deterministic threat assessment based on IP string patterns."""
        start_time = time.perf_counter()

        # Deterministic scenario selection based on IP address string
        if target_ip in ("1.1.1.1", "8.8.8.8") or target_ip.endswith(".1") or target_ip.endswith(".8"):
            scenario = "CLEAN"
        elif target_ip.endswith(".45") or target_ip.endswith(".100") or "198.51" in target_ip:
            scenario = "SUSPICIOUS"
        else:
            # Default or explicit malicious test IP (e.g. 185.220.101.5, 192.0.2.200)
            scenario = "MALICIOUS"

        if scenario == "CLEAN":
            score = ThreatScore(score=0, level=ThreatLevel.CLEAN, confidence=100)
            reputation = ReputationData(
                provider_name="mock",
                status=DataStatus.AVAILABLE,
                total_reports=0,
                distinct_reporters=0,
                categories=["Whitelisted DNS / Trusted Infrastructure"],
                tags=["trusted", "dns-resolver"],
            )
            evidence = [
                EvidenceItem(
                    category="Reputation",
                    description="No abuse reports or malicious indicators found across global WAF telemetry.",
                    source="Mock Provider Engine",
                    severity="INFO",
                )
            ]

        elif scenario == "SUSPICIOUS":
            score = ThreatScore(score=62, level=ThreatLevel.SUSPICIOUS, confidence=85)
            reputation = ReputationData(
                provider_name="mock",
                status=DataStatus.AVAILABLE,
                total_reports=14,
                distinct_reporters=6,
                last_reported_at="2026-09-12 14:22:10 UTC",
                categories=["SSH Brute Force", "Port Scanning"],
                tags=["scanner", "brute-force", "vpn-node"],
            )
            evidence = [
                EvidenceItem(
                    category="WAF Telemetry",
                    description="Detected 48 SSH connection attempts within a 10-minute window.",
                    source="Mock Sentinel Sensor",
                    severity="MEDIUM",
                ),
                EvidenceItem(
                    category="Network Probe",
                    description="Sequential port scan directed at ports 22, 80, 443, and 8080.",
                    source="Mock Probe Detector",
                    severity="MEDIUM",
                ),
            ]

        else:  # MALICIOUS
            score = ThreatScore(score=96, level=ThreatLevel.MALICIOUS, confidence=98)
            reputation = ReputationData(
                provider_name="mock",
                status=DataStatus.AVAILABLE,
                total_reports=142,
                distinct_reporters=38,
                last_reported_at="2026-09-13 10:15:00 UTC",
                categories=["SQL Injection", "Botnet C2", "Exploit Attempt", "Web Spam"],
                tags=["botnet", "sqli", "c2-node", "active-attacker"],
            )
            evidence = [
                EvidenceItem(
                    category="WAF Exploit Attack",
                    description="122 SQL Injection payloads blocked targeting HTTP POST /api/v1/login.",
                    source="WAF Rule Engine (ID: 942100)",
                    severity="HIGH",
                ),
                EvidenceItem(
                    category="C2 Communication",
                    description="Observed active Beacon traffic matching Mirai botnet signature.",
                    source="Threat Intelligence Feed",
                    severity="CRITICAL",
                ),
                EvidenceItem(
                    category="Remote Code Execution",
                    description="Log4j JNDI lookup attempt in User-Agent header string.",
                    source="WAF Log Audit",
                    severity="CRITICAL",
                ),
            ]

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ProviderResult(
            provider_name="mock",
            status=DataStatus.AVAILABLE,
            threat_score=score,
            reputation=reputation,
            evidence=evidence,
            execution_time_ms=elapsed_ms,
        )
