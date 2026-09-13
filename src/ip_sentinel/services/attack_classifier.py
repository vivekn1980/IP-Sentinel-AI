"""WAF Attack Classifier.

Evaluates per-IP WAF traffic metrics, user-agent signals, path patterns, HTTP status
ratios, and temporal regularity to compute evidence-backed attack classifications.
"""

import logging
from typing import Dict, List, Tuple

from ip_sentinel.models.waf_behavior import (
    AttackClassification,
    BehavioralFingerprint,
    BehavioralLevel,
    WAFIPAnalysis,
)

logger = logging.getLogger("ip_sentinel.services.attack_classifier")

# Configurable sensitive path categories
SENSITIVE_PATHS = {
    "CONFIG_DISCOVERY": ["/.env", "/.git", "/config", "/actuator", "/settings.py", "/appsettings.json", "/web.config"],
    "ADMIN_ENUMERATION": ["/admin", "/administrator", "/phpmyadmin", "/cpanel", "/backend", "/dashboard"],
    "CMS_SCAN": ["/wp-login.php", "/wp-admin", "/xmlrpc.php", "/user/login", "/administrator/index.php"],
    "WEB_SCANNER": ["/etc/passwd", "/win.ini", "/cgi-bin", "/shell", "/cmd", "/eval", "/vendor"],
    "CREDENTIAL_ENDPOINT": ["/login", "/signin", "/auth", "/wp-login.php", "/oauth/token", "/api/v1/auth", "/api/login"],
}

KNOWN_BOT_UAS = ["python-requests", "nmap", "hydra", "gobuster", "dirbuster", "sqlmap", "nikto", "curl", "wget", "go-http-client", "credbot"]


class AttackClassifier:
    """Evidence-backed behavioral attack classifier for WAF telemetry."""

    def classify(self, analysis: WAFIPAnalysis) -> Tuple[AttackClassification, int, List[str], List[str], List[str], BehavioralFingerprint]:
        """Classify traffic behavior and return (classification, confidence, supporting_evidence, contradictory_evidence, limitations, fingerprint)."""
        supporting: List[str] = []
        contradictory: List[str] = []
        limitations: List[str] = []

        total_reqs = analysis.total_requests
        if total_reqs < 2:
            limitations.append(f"Low sample size ({total_reqs} request(s)) limits classification accuracy.")
            fingerprint = self._build_fingerprint(analysis, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW, BehavioralLevel.LOW)
            return (
                AttackClassification.UNKNOWN,
                30,
                ["Insufficient requests to establish a definitive behavioral pattern."],
                [],
                limitations,
                fingerprint,
            )

        # 1. Evaluate Metrics
        has_sensitive_probes = (analysis.sensitive_endpoint_hits + analysis.admin_endpoint_hits + analysis.config_file_hits) > 0
        has_auth_probes = analysis.auth_endpoint_hits > 0
        high_404 = analysis.pct_404 >= 40.0
        high_4xx = analysis.pct_4xx >= 50.0
        high_peak_rate = analysis.peak_req_per_sec >= 5.0 or analysis.peak_req_per_min >= 60.0
        single_dominant_ua = analysis.dominant_ua_pct >= 90.0
        high_uri_repetition = analysis.repeated_uri_ratio >= 80.0
        is_known_script_ua = any(bot_name in analysis.dominant_ua.lower() for bot_name in KNOWN_BOT_UAS)

        # 2. Rule Evaluation
        classification = AttackClassification.UNKNOWN
        confidence = 50

        # Scenario A: HTTP Flood
        if high_peak_rate and analysis.is_bursty:
            classification = AttackClassification.HTTP_FLOOD
            confidence = min(95, 75 + int(analysis.peak_req_per_sec * 2))
            supporting.append(f"High peak request rate detected ({analysis.peak_req_per_sec:.1f} req/s, {analysis.peak_req_per_min:.0f} req/min).")
            supporting.append("Traffic exhibits high temporal burstiness.")
            if high_uri_repetition:
                supporting.append(f"{analysis.repeated_uri_ratio:.1f}% of requests targeted repeated URIs.")
            if analysis.pct_2xx > 50.0:
                contradictory.append("Target server responded with 2xx status to majority of flood requests.")

        # Scenario B: Credential Attack
        elif has_auth_probes and (analysis.auth_endpoint_hits >= 3 or (analysis.auth_endpoint_hits >= 1 and total_reqs <= 5)) and (analysis.get_post_ratio < 0.5 or "POST" in analysis.method_distribution):
            classification = AttackClassification.CREDENTIAL_ATTACK
            confidence = 85
            supporting.append(f"Targeted authentication endpoints {analysis.auth_endpoint_hits} time(s).")
            if analysis.pct_403 > 0 or analysis.pct_404 > 0 or analysis.pct_429 > 0:
                supporting.append(f"Authentication requests generated security/rate-limit responses (4xx ratio: {analysis.pct_4xx:.1f}%).")
            if single_dominant_ua:
                supporting.append(f"{analysis.dominant_ua_pct:.1f}% of requests used dominant User-Agent '{analysis.dominant_ua}'.")

        # Scenario C: Web Scanner
        elif has_sensitive_probes or (high_404 and analysis.unique_uri_count >= 3):
            classification = AttackClassification.WEB_SCANNER
            confidence = 90 if has_sensitive_probes else 75
            if analysis.config_file_hits > 0:
                supporting.append(f"Requested {analysis.config_file_hits} configuration file probe path(s) (e.g., /.env, /.git).")
            if analysis.admin_endpoint_hits > 0:
                supporting.append(f"Requested {analysis.admin_endpoint_hits} administrative endpoint path(s).")
            if analysis.sensitive_endpoint_hits > 0:
                supporting.append(f"Requested {analysis.sensitive_endpoint_hits} sensitive endpoint path(s).")
            if high_404:
                supporting.append(f"{analysis.pct_404:.1f}% of requests returned HTTP 404 Not Found.")
            if is_known_script_ua:
                supporting.append(f"User-Agent indicates automated tool/library ('{analysis.dominant_ua}').")

        # Scenario D: Malicious Bot
        elif (high_4xx or is_known_script_ua) and (single_dominant_ua or high_uri_repetition):
            classification = AttackClassification.MALICIOUS_BOT
            confidence = 80
            supporting.append(f"High HTTP 4xx error response ratio ({analysis.pct_4xx:.1f}%).")
            supporting.append(f"Dominant User-Agent '{analysis.dominant_ua}' accounted for {analysis.dominant_ua_pct:.1f}% of requests.")
            if high_uri_repetition:
                supporting.append(f"High request repetition ratio ({analysis.repeated_uri_ratio:.1f}%).")

        # Scenario E: Automated Bot / Suspicious Automation
        elif single_dominant_ua and (high_uri_repetition or analysis.temporal_regularity_score >= 70.0):
            classification = AttackClassification.AUTOMATED_BOT if analysis.temporal_regularity_score >= 70.0 else AttackClassification.SUSPICIOUS_AUTOMATION
            confidence = 70
            supporting.append(f"{analysis.dominant_ua_pct:.1f}% of requests originated from a single User-Agent.")
            supporting.append(f"Temporal regularity score is {analysis.temporal_regularity_score:.1f}/100.")
            if analysis.pct_2xx >= 80.0:
                contradictory.append("High 2xx success rate indicates requests were accepted as valid application traffic.")

        # Scenario F: Normal Client
        elif analysis.pct_2xx >= 70.0 and not has_sensitive_probes and analysis.peak_req_per_sec < 5.0 and analysis.pct_404 < 30.0:
            classification = AttackClassification.NORMAL_CLIENT
            confidence = 85
            supporting.append(f"High successful request ratio ({analysis.pct_2xx:.1f}% 2xx status).")
            supporting.append("No sensitive file or administrative endpoint probes detected.")
            supporting.append(f"Normal peak request rate ({analysis.peak_req_per_sec:.1f} req/s).")

        else:
            classification = AttackClassification.SUSPICIOUS_AUTOMATION if high_uri_repetition else AttackClassification.UNKNOWN
            confidence = 60
            supporting.append("Telemetry exhibits mixed behavioral traits.")
            limitations.append("Traffic patterns do not cleanly match a single threat signature.")

        # Limitations Check
        if not analysis.duration_seconds or analysis.duration_seconds == 0:
            limitations.append("Timestamp telemetry missing or zero duration window; rate calculations estimated.")
        if analysis.cookie_present_ratio == 0.0 and analysis.cookie_absent_ratio == 0.0:
            limitations.append("Cookie telemetry UNAVAILABLE in WAF log format.")

        # 3. Compute Fingerprint
        fingerprint = self._compute_fingerprint(analysis, classification)

        return classification, confidence, supporting, contradictory, limitations, fingerprint

    def _compute_fingerprint(self, analysis: WAFIPAnalysis, classification: AttackClassification) -> BehavioralFingerprint:
        """Calculate qualitative Low/Medium/High levels for behavioral fingerprint dimensions."""
        # Request rate level
        if analysis.peak_req_per_sec >= 10.0 or analysis.peak_req_per_min >= 120.0:
            req_rate_level = BehavioralLevel.HIGH
        elif analysis.peak_req_per_sec >= 2.0 or analysis.peak_req_per_min >= 30.0:
            req_rate_level = BehavioralLevel.MEDIUM
        else:
            req_rate_level = BehavioralLevel.LOW

        # URI diversity level
        if analysis.unique_uri_count >= 10:
            uri_div_level = BehavioralLevel.HIGH
        elif analysis.unique_uri_count >= 3:
            uri_div_level = BehavioralLevel.MEDIUM
        else:
            uri_div_level = BehavioralLevel.LOW

        # UA diversity level
        if analysis.unique_ua_count >= 4:
            ua_div_level = BehavioralLevel.HIGH
        elif analysis.unique_ua_count >= 2:
            ua_div_level = BehavioralLevel.MEDIUM
        else:
            ua_div_level = BehavioralLevel.LOW

        # Status distribution level
        if analysis.pct_4xx >= 50.0 or analysis.pct_5xx >= 20.0:
            status_level = BehavioralLevel.HIGH
        elif analysis.pct_4xx >= 20.0 or analysis.pct_5xx >= 5.0:
            status_level = BehavioralLevel.MEDIUM
        else:
            status_level = BehavioralLevel.LOW

        # Request repetition level
        if analysis.repeated_uri_ratio >= 75.0:
            rep_level = BehavioralLevel.HIGH
        elif analysis.repeated_uri_ratio >= 40.0:
            rep_level = BehavioralLevel.MEDIUM
        else:
            rep_level = BehavioralLevel.LOW

        # Temporal pattern level
        if analysis.temporal_regularity_score >= 75.0 or analysis.is_bursty:
            temp_level = BehavioralLevel.HIGH
        elif analysis.temporal_regularity_score >= 40.0:
            temp_level = BehavioralLevel.MEDIUM
        else:
            temp_level = BehavioralLevel.LOW

        # HTTP method distribution level
        if analysis.get_post_ratio < 0.2 or "POST" in analysis.method_distribution and analysis.method_distribution["POST"] > 5:
            method_level = BehavioralLevel.HIGH
        elif "POST" in analysis.method_distribution:
            method_level = BehavioralLevel.MEDIUM
        else:
            method_level = BehavioralLevel.LOW

        # Sensitive endpoint level
        sensitive_total = analysis.sensitive_endpoint_hits + analysis.admin_endpoint_hits + analysis.config_file_hits + analysis.auth_endpoint_hits
        if sensitive_total >= 3:
            sens_level = BehavioralLevel.HIGH
        elif sensitive_total >= 1:
            sens_level = BehavioralLevel.MEDIUM
        else:
            sens_level = BehavioralLevel.LOW

        # Automation indicators level
        if classification in (AttackClassification.AUTOMATED_BOT, AttackClassification.MALICIOUS_BOT, AttackClassification.WEB_SCANNER, AttackClassification.HTTP_FLOOD, AttackClassification.CREDENTIAL_ATTACK):
            auto_level = BehavioralLevel.HIGH
        elif classification == AttackClassification.SUSPICIOUS_AUTOMATION:
            auto_level = BehavioralLevel.MEDIUM
        else:
            auto_level = BehavioralLevel.LOW

        return BehavioralFingerprint(
            request_rate=req_rate_level,
            uri_diversity=uri_div_level,
            user_agent_diversity=ua_div_level,
            status_distribution=status_level,
            request_repetition=rep_level,
            temporal_pattern=temp_level,
            http_method_distribution=method_level,
            sensitive_endpoint_activity=sens_level,
            automation_indicators=auto_level,
            details={
                "total_requests": analysis.total_requests,
                "peak_req_per_sec": round(analysis.peak_req_per_sec, 2),
                "dominant_ua_pct": round(analysis.dominant_ua_pct, 1),
                "pct_404": round(analysis.pct_404, 1),
            },
        )

    def _build_fingerprint(self, analysis: WAFIPAnalysis, *levels: BehavioralLevel) -> BehavioralFingerprint:
        return BehavioralFingerprint(
            request_rate=levels[0],
            uri_diversity=levels[1],
            user_agent_diversity=levels[2],
            status_distribution=levels[3],
            request_repetition=levels[4],
            temporal_pattern=levels[5],
            http_method_distribution=levels[6],
            sensitive_endpoint_activity=levels[7],
            automation_indicators=levels[8],
        )
