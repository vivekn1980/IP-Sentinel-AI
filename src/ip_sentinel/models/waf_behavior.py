"""WAF Behavioral and Attack Analysis Data Models.

Defines classification Enums, Behavioral Fingerprints, per-IP analysis metrics,
and file-wide WAF analysis results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ip_sentinel.models.threat_intel import EvidenceItem
from ip_sentinel.models.waf_event import WAFEvent


class AttackClassification(Enum):
    """Possible WAF behavioral attack classifications."""

    NORMAL_CLIENT = "NORMAL_CLIENT"
    AUTOMATED_BOT = "AUTOMATED_BOT"
    MALICIOUS_BOT = "MALICIOUS_BOT"
    WEB_SCANNER = "WEB_SCANNER"
    HTTP_FLOOD = "HTTP_FLOOD"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    SUSPICIOUS_AUTOMATION = "SUSPICIOUS_AUTOMATION"
    UNKNOWN = "UNKNOWN"


class BehavioralLevel(Enum):
    """Qualitative level rating for behavioral fingerprint metrics."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class BehavioralFingerprint:
    """Multi-dimensional behavioral vector representing traffic characteristics."""

    request_rate: BehavioralLevel = BehavioralLevel.LOW
    uri_diversity: BehavioralLevel = BehavioralLevel.LOW
    user_agent_diversity: BehavioralLevel = BehavioralLevel.LOW
    status_distribution: BehavioralLevel = BehavioralLevel.LOW
    request_repetition: BehavioralLevel = BehavioralLevel.LOW
    temporal_pattern: BehavioralLevel = BehavioralLevel.LOW
    http_method_distribution: BehavioralLevel = BehavioralLevel.LOW
    sensitive_endpoint_activity: BehavioralLevel = BehavioralLevel.LOW
    automation_indicators: BehavioralLevel = BehavioralLevel.LOW
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WAFIPAnalysis:
    """Aggregated WAF behavioral telemetry, statistics, and classification for a single IP."""

    source_ip: str
    total_requests: int = 0
    duration_seconds: float = 0.0
    avg_req_per_sec: float = 0.0
    peak_req_per_sec: float = 0.0
    avg_req_per_min: float = 0.0
    peak_req_per_min: float = 0.0
    is_bursty: bool = False
    rate_anomaly: bool = False

    # User-Agent analysis
    unique_ua_count: int = 0
    dominant_ua: str = "UNKNOWN"
    dominant_ua_pct: float = 0.0
    missing_ua_pct: float = 0.0
    ua_diversity: float = 0.0

    # URI & Path analysis
    unique_uri_count: int = 0
    most_requested_uri: str = "UNKNOWN"
    repeated_uri_ratio: float = 0.0
    ratio_404_uri: float = 0.0
    sensitive_endpoint_hits: int = 0
    admin_endpoint_hits: int = 0
    config_file_hits: int = 0
    auth_endpoint_hits: int = 0
    uri_category_counts: Dict[str, int] = field(default_factory=dict)

    # HTTP Status distribution
    pct_2xx: float = 0.0
    pct_3xx: float = 0.0
    pct_4xx: float = 0.0
    pct_5xx: float = 0.0
    pct_403: float = 0.0
    pct_404: float = 0.0
    pct_429: float = 0.0

    # Request Pattern analysis
    temporal_regularity_score: float = 0.0  # 0 to 100
    method_distribution: Dict[str, int] = field(default_factory=dict)
    get_post_ratio: float = 0.0

    # Cookie & Request Type analysis
    cookie_present_ratio: float = 0.0
    cookie_absent_ratio: float = 0.0
    request_type_dist: Dict[str, int] = field(default_factory=dict)

    # Behavioral Fingerprint & Classification
    behavioral_fingerprint: BehavioralFingerprint = field(
        default_factory=BehavioralFingerprint
    )
    primary_classification: AttackClassification = AttackClassification.UNKNOWN
    classification_confidence: int = 0  # 0 to 100
    supporting_evidence: List[str] = field(default_factory=list)
    contradictory_evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    # Generated EvidenceItems & Risk Score
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    events: List[WAFEvent] = field(default_factory=list)


@dataclass(frozen=True)
class WAFAnalysisResult:
    """File-wide or batch WAF analysis result aggregating all parsed IPs."""

    file_path: str = ""
    total_events: int = 0
    unique_ips_count: int = 0
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    top_ips: List[WAFIPAnalysis] = field(default_factory=list)
    high_risk_ips: List[WAFIPAnalysis] = field(default_factory=list)
    ip_analyses: Dict[str, WAFIPAnalysis] = field(default_factory=dict)
