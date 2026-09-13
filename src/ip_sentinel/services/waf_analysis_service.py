"""WAF Analysis Service.

Core orchestrator for parsing WAF logs, aggregating per-IP telemetry, calculating
volume/rate/UA/URI/status statistics, generating evidence items, and invoking the
AttackClassifier. Pure business logic with zero UI dependencies.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Tuple

from ip_sentinel.models.threat_intel import DataStatus, EvidenceItem
from ip_sentinel.models.waf_behavior import (
    AttackClassification,
    WAFAnalysisResult,
    WAFIPAnalysis,
)
from ip_sentinel.models.waf_event import WAFEvent
from ip_sentinel.parsers.base import BaseWAFParser
from ip_sentinel.parsers.csv_parser import CSVWAFParser
from ip_sentinel.parsers.json_parser import JSONWAFParser
from ip_sentinel.services.attack_classifier import SENSITIVE_PATHS, AttackClassifier

logger = logging.getLogger("ip_sentinel.services.waf_analysis")


class WAFAnalysisService:
    """Service for analyzing WAF events, computing statistics, and producing classifications."""

    def __init__(self):
        self.csv_parser = CSVWAFParser()
        self.json_parser = JSONWAFParser()
        self.classifier = AttackClassifier()

    def analyze_file(self, file_path: str, parser: Optional[BaseWAFParser] = None) -> WAFAnalysisResult:
        """Parse and analyze a WAF log file from disk."""
        if parser is None:
            if file_path.lower().endswith(".json") or file_path.lower().endswith(".jsonl"):
                parser = self.json_parser
            else:
                parser = self.csv_parser

        events = parser.parse_file(file_path)
        return self.analyze_events(events, file_path=file_path)

    def analyze_events(self, events: List[WAFEvent], file_path: str = "") -> WAFAnalysisResult:
        """Analyze a list of normalized WAFEvents."""
        if not events:
            return WAFAnalysisResult(file_path=file_path, total_events=0, unique_ips_count=0)

        # Group events by source IP
        grouped: Dict[str, List[WAFEvent]] = {}
        time_stamps: List[str] = []

        for evt in events:
            grouped.setdefault(evt.source_ip, []).append(evt)
            if evt.timestamp:
                time_stamps.append(evt.timestamp)

        # Time range calculation
        time_start: Optional[str] = min(time_stamps) if time_stamps else None
        time_end: Optional[str] = max(time_stamps) if time_stamps else None

        # Analyze each IP
        ip_analyses: Dict[str, WAFIPAnalysis] = {}
        for ip, ip_events in grouped.items():
            ip_analysis = self.analyze_ip_events(ip, ip_events)
            ip_analyses[ip] = ip_analysis

        # Sort top IPs and high risk IPs
        sorted_by_reqs = sorted(ip_analyses.values(), key=lambda a: a.total_requests, reverse=True)
        sorted_by_risk = sorted(ip_analyses.values(), key=lambda a: a.risk_score, reverse=True)

        return WAFAnalysisResult(
            file_path=file_path,
            total_events=len(events),
            unique_ips_count=len(grouped),
            time_range_start=time_start,
            time_range_end=time_end,
            top_ips=sorted_by_reqs[:10],
            high_risk_ips=[a for a in sorted_by_risk if a.risk_score >= 50][:10],
            ip_analyses=ip_analyses,
        )

    def analyze_ip_events(self, ip: str, events: List[WAFEvent]) -> WAFIPAnalysis:
        """Calculate telemetry, metrics, fingerprint, and classification for a single IP's events."""
        total_requests = len(events)
        if total_requests == 0:
            return WAFIPAnalysis(source_ip=ip)

        # Time duration & rate calculations
        parsed_times: List[datetime] = []
        for e in events:
            if e.timestamp:
                dt = self._parse_iso_timestamp(e.timestamp)
                if dt:
                    parsed_times.append(dt)

        parsed_times.sort()
        duration_sec = 0.0
        if len(parsed_times) >= 2:
            duration_sec = max(0.1, (parsed_times[-1] - parsed_times[0]).total_seconds())

        avg_req_per_sec = (total_requests / duration_sec) if duration_sec > 0 else float(total_requests)
        avg_req_per_min = avg_req_per_sec * 60.0

        # Peak rates & burst calculation
        peak_req_per_sec, peak_req_per_min, is_bursty = self._calculate_peak_rates(parsed_times, total_requests, duration_sec)

        # User-Agent analysis
        uas = [e.user_agent for e in events if e.user_agent]
        unique_uas = set(uas)
        unique_ua_count = len(unique_uas)
        missing_ua_count = sum(1 for ua in uas if ua in ("UNKNOWN", "", None))
        missing_ua_pct = (missing_ua_count / total_requests) * 100.0 if total_requests else 0.0

        ua_counts: Dict[str, int] = {}
        for ua in uas:
            ua_counts[ua] = ua_counts.get(ua, 0) + 1

        dominant_ua = max(ua_counts, key=ua_counts.get) if ua_counts else "UNKNOWN"
        dominant_ua_count = ua_counts.get(dominant_ua, 0)
        dominant_ua_pct = (dominant_ua_count / total_requests) * 100.0 if total_requests else 0.0
        ua_diversity = (unique_ua_count / total_requests) if total_requests else 0.0

        # URI & Path analysis
        uris = [e.uri_path for e in events if e.uri_path]
        unique_uris = set(uris)
        unique_uri_count = len(unique_uris)

        uri_counts: Dict[str, int] = {}
        for u in uris:
            uri_counts[u] = uri_counts.get(u, 0) + 1

        most_requested_uri = max(uri_counts, key=uri_counts.get) if uri_counts else "UNKNOWN"
        max_uri_count = uri_counts.get(most_requested_uri, 0)
        repeated_uri_ratio = (max_uri_count / total_requests) * 100.0 if total_requests else 0.0

        # Path categories & probes
        config_hits = 0
        admin_hits = 0
        sensitive_hits = 0
        auth_hits = 0
        uri_cat_counts: Dict[str, int] = {}

        for uri in uris:
            uri_lc = uri.lower()
            if any(p in uri_lc for p in SENSITIVE_PATHS["CONFIG_DISCOVERY"]):
                config_hits += 1
                uri_cat_counts["CONFIG_DISCOVERY"] = uri_cat_counts.get("CONFIG_DISCOVERY", 0) + 1
            if any(p in uri_lc for p in SENSITIVE_PATHS["ADMIN_ENUMERATION"]):
                admin_hits += 1
                uri_cat_counts["ADMIN_ENUMERATION"] = uri_cat_counts.get("ADMIN_ENUMERATION", 0) + 1
            if any(p in uri_lc for p in SENSITIVE_PATHS["WEB_SCANNER"]):
                sensitive_hits += 1
                uri_cat_counts["WEB_SCANNER"] = uri_cat_counts.get("WEB_SCANNER", 0) + 1
            if any(p in uri_lc for p in SENSITIVE_PATHS["CREDENTIAL_ENDPOINT"]):
                auth_hits += 1
                uri_cat_counts["CREDENTIAL_ENDPOINT"] = uri_cat_counts.get("CREDENTIAL_ENDPOINT", 0) + 1

        # HTTP Status distribution
        statuses = [e.status_code for e in events if e.status_code is not None]
        c_2xx = sum(1 for s in statuses if 200 <= s < 300)
        c_3xx = sum(1 for s in statuses if 300 <= s < 400)
        c_4xx = sum(1 for s in statuses if 400 <= s < 500)
        c_5xx = sum(1 for s in statuses if 500 <= s < 600)
        c_403 = sum(1 for s in statuses if s == 403)
        c_404 = sum(1 for s in statuses if s == 404)
        c_429 = sum(1 for s in statuses if s == 429)

        total_st = len(statuses) or 1
        pct_2xx = (c_2xx / total_st) * 100.0
        pct_3xx = (c_3xx / total_st) * 100.0
        pct_4xx = (c_4xx / total_st) * 100.0
        pct_5xx = (c_5xx / total_st) * 100.0
        pct_403 = (c_403 / total_st) * 100.0
        pct_404 = (c_404 / total_st) * 100.0
        pct_429 = (c_429 / total_st) * 100.0
        ratio_404_uri = pct_404

        # HTTP Method distribution
        methods = [e.http_method for e in events if e.http_method]
        method_counts: Dict[str, int] = {}
        for m in methods:
            method_counts[m] = method_counts.get(m, 0) + 1

        get_count = method_counts.get("GET", 0)
        post_count = method_counts.get("POST", 0)
        get_post_ratio = (get_count / post_count) if post_count > 0 else float(get_count)

        # Temporal regularity score (0 to 100)
        temporal_regularity = self._calculate_temporal_regularity(parsed_times)

        # Construct preliminary analysis for classifier
        prelim = WAFIPAnalysis(
            source_ip=ip,
            total_requests=total_requests,
            duration_seconds=duration_sec,
            avg_req_per_sec=avg_req_per_sec,
            peak_req_per_sec=peak_req_per_sec,
            avg_req_per_min=avg_req_per_min,
            peak_req_per_min=peak_req_per_min,
            is_bursty=is_bursty,
            rate_anomaly=(peak_req_per_sec > avg_req_per_sec * 3 and peak_req_per_sec >= 5.0),
            unique_ua_count=unique_ua_count,
            dominant_ua=dominant_ua,
            dominant_ua_pct=dominant_ua_pct,
            missing_ua_pct=missing_ua_pct,
            ua_diversity=ua_diversity,
            unique_uri_count=unique_uri_count,
            most_requested_uri=most_requested_uri,
            repeated_uri_ratio=repeated_uri_ratio,
            ratio_404_uri=ratio_404_uri,
            sensitive_endpoint_hits=sensitive_hits,
            admin_endpoint_hits=admin_hits,
            config_file_hits=config_hits,
            auth_endpoint_hits=auth_hits,
            uri_category_counts=uri_cat_counts,
            pct_2xx=pct_2xx,
            pct_3xx=pct_3xx,
            pct_4xx=pct_4xx,
            pct_5xx=pct_5xx,
            pct_403=pct_403,
            pct_404=pct_404,
            pct_429=pct_429,
            temporal_regularity_score=temporal_regularity,
            method_distribution=method_counts,
            get_post_ratio=get_post_ratio,
            cookie_present_ratio=0.0,
            cookie_absent_ratio=0.0,
            events=events,
        )

        # Run Classifier
        classification, confidence, supporting, contradictory, limitations, fingerprint = self.classifier.classify(prelim)

        # Build EvidenceItems
        evidence_items = self._generate_waf_evidence_items(prelim, classification, supporting)

        # Calculate Risk Score
        risk_score = self._calculate_waf_risk_score(prelim, classification, confidence)

        return WAFIPAnalysis(
            source_ip=ip,
            total_requests=total_requests,
            duration_seconds=duration_sec,
            avg_req_per_sec=avg_req_per_sec,
            peak_req_per_sec=peak_req_per_sec,
            avg_req_per_min=avg_req_per_min,
            peak_req_per_min=peak_req_per_min,
            is_bursty=is_bursty,
            rate_anomaly=prelim.rate_anomaly,
            unique_ua_count=unique_ua_count,
            dominant_ua=dominant_ua,
            dominant_ua_pct=dominant_ua_pct,
            missing_ua_pct=missing_ua_pct,
            ua_diversity=ua_diversity,
            unique_uri_count=unique_uri_count,
            most_requested_uri=most_requested_uri,
            repeated_uri_ratio=repeated_uri_ratio,
            ratio_404_uri=ratio_404_uri,
            sensitive_endpoint_hits=sensitive_hits,
            admin_endpoint_hits=admin_hits,
            config_file_hits=config_hits,
            auth_endpoint_hits=auth_hits,
            uri_category_counts=uri_cat_counts,
            pct_2xx=pct_2xx,
            pct_3xx=pct_3xx,
            pct_4xx=pct_4xx,
            pct_5xx=pct_5xx,
            pct_403=pct_403,
            pct_404=pct_404,
            pct_429=pct_429,
            temporal_regularity_score=temporal_regularity,
            method_distribution=method_counts,
            get_post_ratio=get_post_ratio,
            cookie_present_ratio=0.0,
            cookie_absent_ratio=0.0,
            behavioral_fingerprint=fingerprint,
            primary_classification=classification,
            classification_confidence=confidence,
            supporting_evidence=supporting,
            contradictory_evidence=contradictory,
            limitations=limitations,
            evidence_items=evidence_items,
            risk_score=risk_score,
            events=events,
        )

    def _generate_waf_evidence_items(self, analysis: WAFIPAnalysis, classification: AttackClassification, supporting: List[str]) -> List[EvidenceItem]:
        """Convert WAF behavioral findings into structured EvidenceItem records."""
        items: List[EvidenceItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Classification Item
        severity = "INFO"
        if classification in (AttackClassification.WEB_SCANNER, AttackClassification.HTTP_FLOOD, AttackClassification.CREDENTIAL_ATTACK, AttackClassification.MALICIOUS_BOT):
            severity = "HIGH"
        elif classification in (AttackClassification.AUTOMATED_BOT, AttackClassification.SUSPICIOUS_AUTOMATION):
            severity = "MEDIUM"
        elif classification == AttackClassification.NORMAL_CLIENT:
            severity = "INFO"

        items.append(
            EvidenceItem(
                source="WAF",
                category="BEHAVIOR/WAF",
                severity=severity,
                confidence=analysis.classification_confidence if hasattr(analysis, "classification_confidence") else 80,
                observation=f"WAF behavioral classification: {classification.value}",
                description=f"WAF behavioral classification: {classification.value}",
                timestamp=now_iso,
                supporting_data={"classification": classification.value, "total_requests": analysis.total_requests},
                status=DataStatus.AVAILABLE,
            )
        )

        # Specific Findings
        if analysis.config_file_hits > 0 or analysis.admin_endpoint_hits > 0 or analysis.sensitive_endpoint_hits > 0:
            items.append(
                EvidenceItem(
                    source="WAF",
                    category="BEHAVIOR/WAF",
                    severity="HIGH",
                    confidence=90,
                    observation=f"Sensitive endpoint probes detected ({analysis.config_file_hits} config, {analysis.admin_endpoint_hits} admin, {analysis.sensitive_endpoint_hits} scanner probes).",
                    timestamp=now_iso,
                    supporting_data={"config_hits": analysis.config_file_hits, "admin_hits": analysis.admin_endpoint_hits},
                )
            )

        if analysis.auth_endpoint_hits > 0 and classification in (AttackClassification.CREDENTIAL_ATTACK, AttackClassification.MALICIOUS_BOT):
            items.append(
                EvidenceItem(
                    source="WAF",
                    category="BEHAVIOR/WAF",
                    severity="HIGH",
                    confidence=85,
                    observation=f"Authentication endpoint targeted ({analysis.auth_endpoint_hits} request(s)).",
                    timestamp=now_iso,
                    supporting_data={"auth_hits": analysis.auth_endpoint_hits},
                )
            )

        if analysis.pct_404 >= 50.0:
            items.append(
                EvidenceItem(
                    source="WAF",
                    category="BEHAVIOR/WAF",
                    severity="MEDIUM",
                    confidence=85,
                    observation=f"{analysis.pct_404:.1f}% of WAF requests returned HTTP 404 Not Found.",
                    timestamp=now_iso,
                    supporting_data={"pct_404": analysis.pct_404},
                )
            )

        if analysis.repeated_uri_ratio >= 80.0 and analysis.total_requests >= 5:
            items.append(
                EvidenceItem(
                    source="WAF",
                    category="BEHAVIOR/WAF",
                    severity="MEDIUM",
                    confidence=80,
                    observation=f"{analysis.repeated_uri_ratio:.1f}% of requests targeted the same URI ('{analysis.most_requested_uri}').",
                    timestamp=now_iso,
                    supporting_data={"most_requested_uri": analysis.most_requested_uri},
                )
            )

        if analysis.is_bursty or analysis.peak_req_per_sec >= 5.0:
            items.append(
                EvidenceItem(
                    source="WAF",
                    category="BEHAVIOR/WAF",
                    severity="HIGH" if analysis.peak_req_per_sec >= 10.0 else "MEDIUM",
                    confidence=85,
                    observation=f"High request-rate burst detected (peak {analysis.peak_req_per_sec:.1f} req/s).",
                    timestamp=now_iso,
                    supporting_data={"peak_req_per_sec": analysis.peak_req_per_sec},
                )
            )

        return items

    def _calculate_waf_risk_score(self, analysis: WAFIPAnalysis, classification: AttackClassification, confidence: int) -> int:
        """Compute 0 to 100 risk score based on WAF attack classification and behavioral metrics."""
        base_score = 0
        if classification == AttackClassification.HTTP_FLOOD:
            base_score = 90
        elif classification in (AttackClassification.WEB_SCANNER, AttackClassification.CREDENTIAL_ATTACK):
            base_score = 85
        elif classification == AttackClassification.MALICIOUS_BOT:
            base_score = 75
        elif classification == AttackClassification.AUTOMATED_BOT:
            base_score = 45
        elif classification == AttackClassification.SUSPICIOUS_AUTOMATION:
            base_score = 40
        elif classification == AttackClassification.NORMAL_CLIENT:
            base_score = 5
        else:
            base_score = 25

        # Adjust score by specific indicators
        if (analysis.config_file_hits + analysis.admin_endpoint_hits + analysis.sensitive_endpoint_hits) > 0:
            base_score = max(base_score, 80)
        if analysis.pct_404 >= 70.0:
            base_score += 10
        if analysis.peak_req_per_sec >= 10.0:
            base_score += 10

        return max(0, min(100, int(base_score * (confidence / 100.0) + (base_score * 0.2))))

    def _calculate_peak_rates(self, times: List[datetime], total_reqs: int, duration_sec: float) -> Tuple[float, float, bool]:
        """Compute peak req/s, peak req/min, and temporal burstiness indicator."""
        if not times or len(times) < 2:
            rate_sec = (total_reqs / duration_sec) if duration_sec > 0 else float(total_reqs)
            return rate_sec, rate_sec * 60.0, False

        # Bucket requests per second
        sec_buckets: Dict[int, int] = {}
        min_buckets: Dict[int, int] = {}

        for t in times:
            s_key = int(t.timestamp())
            m_key = s_key // 60
            sec_buckets[s_key] = sec_buckets.get(s_key, 0) + 1
            min_buckets[m_key] = min_buckets.get(m_key, 0) + 1

        peak_sec = float(max(sec_buckets.values())) if sec_buckets else 0.0
        peak_min = float(max(min_buckets.values())) if min_buckets else 0.0
        avg_sec = total_reqs / duration_sec if duration_sec > 0 else 1.0

        is_bursty = (peak_sec >= 3.0 and peak_sec > avg_sec * 2.5)
        return peak_sec, peak_min, is_bursty

    def _calculate_temporal_regularity(self, times: List[datetime]) -> float:
        """Calculate temporal interval regularity score (0 to 100)."""
        if len(times) < 3:
            return 0.0

        intervals = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
        if not intervals or all(i == 0 for i in intervals):
            return 95.0

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return 100.0

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / mean_interval  # Coefficient of Variation

        # Low CV (< 0.3) indicates high automated regularity
        regularity = max(0.0, min(100.0, (1.0 - min(1.0, cv)) * 100.0))
        return round(regularity, 1)

    def _parse_iso_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO 8601 or common timestamp format safely."""
        if not ts_str:
            return None
        clean_ts = ts_str.replace("Z", "+00:00").strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
        return None
