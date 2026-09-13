"""AbuseIPDB Threat Intelligence Provider adapter."""

import datetime
import logging
import time
from typing import Any, Dict, List, Optional

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

logger = logging.getLogger("ip_sentinel.providers.abuseipdb")

ABUSEIPDB_CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    9: "POP3 Brute-Force",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploit Attempt",
    21: "Web App Attack",
    22: "SSH Brute-Force",
    23: "IoT Targeted",
}


class AbuseIPDBProvider(BaseIntelProvider):
    """Passive AbuseIPDB v2 API provider querying IP reputation telemetry."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, timeout: float = 4.0, cache_ttl: int = 3600):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache = CacheManager()
        self.config_mgr = ConfigManager()

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    def _get_api_key(self) -> Optional[str]:
        return self.config_mgr.secret_store.get_secret("abuseipdb")

    def is_configured(self) -> bool:
        key = self._get_api_key()
        return bool(key and len(key.strip()) > 5)

    def health_check(self) -> bool:
        return self.is_configured()

    def query_ip(self, target_ip: str) -> ProviderResult:
        """Query AbuseIPDB API for target IP threat telemetry."""
        start_time = time.perf_counter()
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if not self.is_configured():
            return ProviderResult(
                provider_name="abuseipdb",
                status=DataStatus.NOT_CONFIGURED,
                error_message="AbuseIPDB API key not configured.",
            )

        cache_key = f"abuseipdb_{target_ip}"
        cached = self.cache.get(cache_key)
        if cached and isinstance(cached, dict):
            logger.info(f"Returning cached AbuseIPDB data for {target_ip}")
            return self._dict_to_provider_result(cached)

        api_key = self._get_api_key()
        headers = {
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "IP-Sentinel-AI/2.0",
        }
        params = {
            "ipAddress": target_ip,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            resp = requests.get(self.API_URL, headers=headers, params=params, timeout=self.timeout)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 401:
                return ProviderResult(
                    provider_name="abuseipdb",
                    status=DataStatus.ERROR,
                    error_message="Invalid AbuseIPDB API key (HTTP 401 Unauthorized)",
                    execution_time_ms=elapsed_ms,
                )

            if resp.status_code == 429:
                return ProviderResult(
                    provider_name="abuseipdb",
                    status=DataStatus.RATE_LIMITED,
                    error_message="AbuseIPDB Rate limit exceeded (HTTP 429)",
                    execution_time_ms=elapsed_ms,
                )

            if resp.status_code != 200:
                return ProviderResult(
                    provider_name="abuseipdb",
                    status=DataStatus.ERROR,
                    error_message=f"AbuseIPDB API returned status HTTP {resp.status_code}",
                    execution_time_ms=elapsed_ms,
                )

            json_data = resp.json()
            data = json_data.get("data", {})
            result = self._parse_abuseipdb_response(target_ip, data, elapsed_ms, now_str)

            # Persist to cache
            self.cache.set(cache_key, self._provider_result_to_dict(result), ttl_seconds=self.cache_ttl)
            return result

        except requests.exceptions.Timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="abuseipdb",
                status=DataStatus.ERROR,
                error_message=f"AbuseIPDB query timed out after {self.timeout}s",
                execution_time_ms=elapsed_ms,
            )
        except Exception as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"AbuseIPDB error for {target_ip}: {err}")
            return ProviderResult(
                provider_name="abuseipdb",
                status=DataStatus.ERROR,
                error_message=f"AbuseIPDB query exception: {err}",
                execution_time_ms=elapsed_ms,
            )

    def _parse_abuseipdb_response(self, target_ip: str, data: Dict[str, Any], elapsed_ms: float, timestamp: str) -> ProviderResult:
        score_val = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        num_distinct = data.get("numDistinctUsers", 0)
        last_reported = data.get("lastReportedAt")
        isp = data.get("isp")
        domain = data.get("domain")
        usage_type = data.get("usageType")

        # Map categories
        cat_set = set()
        reports = data.get("reports", [])
        if isinstance(reports, list):
            for r in reports:
                cats = r.get("categories", [])
                for cid in cats:
                    cname = ABUSEIPDB_CATEGORY_MAP.get(cid, f"Category {cid}")
                    cat_set.add(cname)

        categories_list = sorted(list(cat_set))

        # Map threat level
        if score_val >= 80:
            level = ThreatLevel.CRITICAL if score_val >= 90 else ThreatLevel.HIGH
        elif score_val >= 40:
            level = ThreatLevel.MEDIUM
        elif score_val > 0:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.VERY_LOW

        threat_score = ThreatScore(
            score=score_val,
            level=level,
            confidence=90 if total_reports > 0 else 50,
            status=DataStatus.AVAILABLE,
        )

        reputation = ReputationData(
            provider_name="abuseipdb",
            status=DataStatus.AVAILABLE,
            abuse_score=score_val,
            total_reports=total_reports,
            distinct_reporters=num_distinct,
            last_reported_at=last_reported,
            categories=categories_list,
            tags=[usage_type] if usage_type else [],
            raw_response={},
        )

        # Build evidence items
        evidence_items = []
        if total_reports > 0:
            sev = "HIGH" if score_val >= 75 else ("MEDIUM" if score_val >= 30 else "LOW")
            evidence_items.append(
                EvidenceItem(
                    source="AbuseIPDB",
                    category="REPUTATION",
                    severity=sev,
                    confidence=85,
                    observation=f"AbuseIPDB report score {score_val}% based on {total_reports} reports from {num_distinct} distinct sources.",
                    timestamp=last_reported or timestamp,
                    supporting_data={"categories": categories_list, "domain": domain, "usage_type": usage_type},
                )
            )
        else:
            evidence_items.append(
                EvidenceItem(
                    source="AbuseIPDB",
                    category="REPUTATION",
                    severity="INFO",
                    confidence=70,
                    observation="Zero abuse reports filed in AbuseIPDB database within the last 90 days.",
                    timestamp=timestamp,
                )
            )

        return ProviderResult(
            provider_name="abuseipdb",
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
            "total_reports": res.reputation.total_reports if res.reputation else 0,
            "distinct_reporters": res.reputation.distinct_reporters if res.reputation else 0,
            "last_reported_at": res.reputation.last_reported_at if res.reputation else None,
            "categories": res.reputation.categories if res.reputation else [],
            "error_message": res.error_message,
        }

    def _dict_to_provider_result(self, d: Dict[str, Any]) -> ProviderResult:
        score_val = d.get("score", 0)
        level_str = d.get("level", "VERY_LOW")
        level = getattr(ThreatLevel, level_str, ThreatLevel.VERY_LOW)

        threat_score = ThreatScore(score=score_val, level=level, confidence=90, status=DataStatus.AVAILABLE)
        reputation = ReputationData(
            provider_name="abuseipdb",
            status=DataStatus.AVAILABLE,
            abuse_score=score_val,
            total_reports=d.get("total_reports", 0),
            distinct_reporters=d.get("distinct_reporters", 0),
            last_reported_at=d.get("last_reported_at"),
            categories=d.get("categories", []),
        )

        return ProviderResult(
            provider_name="abuseipdb",
            status=DataStatus(d.get("status", DataStatus.AVAILABLE.value)),
            threat_score=threat_score,
            reputation=reputation,
            evidence=[],
            error_message=d.get("error_message"),
        )
