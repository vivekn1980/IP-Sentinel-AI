"""VirusTotal v3 IP Threat Intelligence Provider adapter."""

import datetime
import logging
import time
from typing import Any, Dict, Optional

import requests

from ip_sentinel.core.cache import CacheManager
from ip_sentinel.core.config import ConfigManager
from ip_sentinel.models.threat_intel import (
    DataStatus,
    EvidenceItem,
    ProviderResult,
    ReputationData,
    ThreatLevel,
    ThreatScore,
)
from ip_sentinel.providers.base import BaseIntelProvider

logger = logging.getLogger("ip_sentinel.providers.virustotal")


class VirusTotalProvider(BaseIntelProvider):
    """Passive VirusTotal v3 API provider querying multi-engine AV/threat reputation."""

    API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def __init__(self, timeout: float = 4.0, cache_ttl: int = 3600):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache = CacheManager()
        self.config_mgr = ConfigManager()

    @property
    def provider_name(self) -> str:
        return "virustotal"

    def _get_api_key(self) -> Optional[str]:
        return self.config_mgr.secret_store.get_secret("virustotal")

    def is_configured(self) -> bool:
        key = self._get_api_key()
        return bool(key and len(key.strip()) > 5)

    def health_check(self) -> bool:
        return self.is_configured()

    def query_ip(self, target_ip: str) -> ProviderResult:
        """Query VirusTotal v3 API for target IP telemetry."""
        start_time = time.perf_counter()
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if not self.is_configured():
            return ProviderResult(
                provider_name="virustotal",
                status=DataStatus.NOT_CONFIGURED,
                error_message="VirusTotal API key not configured.",
            )

        cache_key = f"virustotal_{target_ip}"
        cached = self.cache.get(cache_key)
        if cached and isinstance(cached, dict):
            logger.info(f"Returning cached VirusTotal data for {target_ip}")
            return self._dict_to_provider_result(cached)

        api_key = self._get_api_key()
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "IP-Sentinel-AI/2.0",
        }
        url = self.API_URL.format(ip=target_ip)

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 401:
                return ProviderResult(
                    provider_name="virustotal",
                    status=DataStatus.ERROR,
                    error_message="Invalid VirusTotal API key (HTTP 401 Unauthorized)",
                    execution_time_ms=elapsed_ms,
                )

            if resp.status_code == 429:
                return ProviderResult(
                    provider_name="virustotal",
                    status=DataStatus.RATE_LIMITED,
                    error_message="VirusTotal Rate limit exceeded (HTTP 429)",
                    execution_time_ms=elapsed_ms,
                )

            if resp.status_code != 200:
                return ProviderResult(
                    provider_name="virustotal",
                    status=DataStatus.ERROR,
                    error_message=f"VirusTotal API returned status HTTP {resp.status_code}",
                    execution_time_ms=elapsed_ms,
                )

            json_data = resp.json()
            attributes = json_data.get("data", {}).get("attributes", {})
            result = self._parse_virustotal_response(target_ip, attributes, elapsed_ms, now_str)

            # Persist to cache
            self.cache.set(cache_key, self._provider_result_to_dict(result), ttl_seconds=self.cache_ttl)
            return result

        except requests.exceptions.Timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="virustotal",
                status=DataStatus.ERROR,
                error_message=f"VirusTotal query timed out after {self.timeout}s",
                execution_time_ms=elapsed_ms,
            )
        except Exception as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"VirusTotal error for {target_ip}: {err}")
            return ProviderResult(
                provider_name="virustotal",
                status=DataStatus.ERROR,
                error_message=f"VirusTotal query exception: {err}",
                execution_time_ms=elapsed_ms,
            )

    def _parse_virustotal_response(self, target_ip: str, attrs: Dict[str, Any], elapsed_ms: float, timestamp: str) -> ProviderResult:
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        rep_score = attrs.get("reputation", 0)

        # Calculate normalized threat score (0-100)
        if total_engines > 0 and malicious > 0:
            pct_malicious = (malicious / total_engines) * 100.0
            score_val = min(100, int(pct_malicious * 5.0) + (10 if malicious > 1 else 0))
        else:
            score_val = 0

        if malicious >= 5:
            level = ThreatLevel.CRITICAL
        elif malicious >= 2:
            level = ThreatLevel.HIGH
        elif malicious == 1 or suspicious > 0:
            level = ThreatLevel.MEDIUM
        else:
            level = ThreatLevel.VERY_LOW

        threat_score = ThreatScore(
            score=score_val,
            level=level,
            confidence=95 if total_engines > 0 else 50,
            status=DataStatus.AVAILABLE,
        )

        reputation = ReputationData(
            provider_name="virustotal",
            status=DataStatus.AVAILABLE,
            abuse_score=score_val,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
            categories=[f"AV Detections: {malicious}/{total_engines}"],
            tags=attrs.get("tags", []),
        )

        evidence_items = []
        if malicious > 0 or suspicious > 0:
            sev = "HIGH" if malicious >= 3 else ("MEDIUM" if malicious >= 1 else "LOW")
            obs = f"VirusTotal flagged IP across {malicious} malicious and {suspicious} suspicious security vendor engines (out of {total_engines} total scanners)."
            evidence_items.append(
                EvidenceItem(
                    source="VirusTotal",
                    category="THREAT_INTELLIGENCE",
                    severity=sev,
                    confidence=90,
                    observation=obs,
                    timestamp=timestamp,
                    supporting_data={"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected},
                )
            )
        else:
            evidence_items.append(
                EvidenceItem(
                    source="VirusTotal",
                    category="THREAT_INTELLIGENCE",
                    severity="INFO",
                    confidence=85,
                    observation=f"Clean status across {harmless + undetected} security vendor engines in VirusTotal database.",
                    timestamp=timestamp,
                )
            )

        return ProviderResult(
            provider_name="virustotal",
            status=DataStatus.AVAILABLE,
            threat_score=threat_score,
            reputation=reputation,
            evidence=evidence_items,
            execution_time_ms=elapsed_ms,
        )

    def _provider_result_to_dict(self, res: ProviderResult) -> Dict[str, Any]:
        return {
            "provider_name": res.provider_name,
            "status": res.status.value,
            "score": res.threat_score.score if res.threat_score else 0,
            "level": res.threat_score.level.value if res.threat_score else "UNKNOWN",
            "malicious_count": res.reputation.malicious_count if res.reputation else 0,
            "suspicious_count": res.reputation.suspicious_count if res.reputation else 0,
            "harmless_count": res.reputation.harmless_count if res.reputation else 0,
            "undetected_count": res.reputation.undetected_count if res.reputation else 0,
            "error_message": res.error_message,
        }

    def _dict_to_provider_result(self, d: Dict[str, Any]) -> ProviderResult:
        score_val = d.get("score", 0)
        level_str = d.get("level", "VERY_LOW")
        level = getattr(ThreatLevel, level_str, ThreatLevel.VERY_LOW)

        threat_score = ThreatScore(score=score_val, level=level, confidence=90, status=DataStatus.AVAILABLE)
        reputation = ReputationData(
            provider_name="virustotal",
            status=DataStatus.AVAILABLE,
            abuse_score=score_val,
            malicious_count=d.get("malicious_count", 0),
            suspicious_count=d.get("suspicious_count", 0),
            harmless_count=d.get("harmless_count", 0),
            undetected_count=d.get("undetected_count", 0),
        )

        return ProviderResult(
            provider_name="virustotal",
            status=DataStatus(d.get("status", DataStatus.AVAILABLE.value)),
            threat_score=threat_score,
            reputation=reputation,
            evidence=[],
            error_message=d.get("error_message"),
        )
