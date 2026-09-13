"""Normalized threat intelligence, network, and evidence correlation data models (DTOs).

Phase 3 updates: Evidence correlation, WAF context, Threat Intelligence provider DTOs,
and multi-source risk assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DataStatus(Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    RATE_LIMITED = "RATE_LIMITED"
    UNKNOWN = "UNKNOWN"


class ThreatLevel(Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class WAFContext:
    """Optional Web Application Firewall (WAF) event correlation context."""
    request_count: int = 0
    time_window: str = "10m"
    http_method: Optional[str] = None
    rule_triggered: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    http_status: Optional[int] = None
    client_ip: Optional[str] = None


@dataclass(frozen=True)
class ThreatScore:
    """Normalized evidence-backed threat score metric scaled 0 to 100."""
    score: int  # 0 to 100
    level: ThreatLevel
    confidence: int = 100  # 0 to 100 percentage
    status: DataStatus = DataStatus.AVAILABLE
    conflicting_evidence: bool = False
    conflict_notes: Optional[str] = None


@dataclass(frozen=True)
class RDAPData:
    """Registration Data Access Protocol (RDAP) network registration details."""
    status: DataStatus = DataStatus.UNAVAILABLE
    ip_address: Optional[str] = None
    ip_version: Optional[int] = None
    network_name: Optional[str] = None
    cidr: Optional[str] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    admin_contact: Optional[str] = None
    abuse_contact: Optional[str] = None
    registry: Optional[str] = None
    lookup_timestamp: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass(frozen=True)
class ASNData:
    """Autonomous System Number (ASN) and routing telemetry."""
    status: DataStatus = DataStatus.UNAVAILABLE
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    network_prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    error_message: Optional[str] = None


@dataclass(frozen=True)
class GeoIPData:
    """Normalized network-level geolocation metadata."""
    status: DataStatus = DataStatus.UNAVAILABLE
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    timezone: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    disclaimer: str = "GeoIP information represents approximate network geolocation and does not identify the physical location of an attacker."
    error_message: Optional[str] = None


@dataclass(frozen=True)
class DNSData:
    """Comprehensive DNS record resolution telemetry."""
    status: DataStatus = DataStatus.UNAVAILABLE
    hostname: Optional[str] = None
    ptr_records: List[str] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass(frozen=True)
class ReputationData:
    """Reputation metrics, categories, and report metrics from an intelligence provider."""
    provider_name: str
    status: DataStatus = DataStatus.AVAILABLE
    abuse_score: int = 0  # 0 to 100
    total_reports: int = 0
    distinct_reporters: int = 0
    last_reported_at: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass(frozen=True)
class EvidenceItem:
    """Normalized structured evidence item supporting threat assessment."""
    source: str
    category: str  # REPUTATION, NETWORK, ASN, DNS, GEOLOCATION, WAF, BEHAVIOR, THREAT_INTELLIGENCE, HISTORICAL
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: int = 80  # 0 to 100
    observation: str = ""
    description: str = ""
    timestamp: Optional[str] = None
    supporting_data: Dict[str, Any] = field(default_factory=dict)
    status: DataStatus = DataStatus.AVAILABLE

    def __post_init__(self):
        if not self.observation and self.description:
            object.__setattr__(self, "observation", self.description)
        elif not self.description and self.observation:
            object.__setattr__(self, "description", self.observation)


@dataclass(frozen=True)
class ProviderResult:
    """Result payload from a single intelligence provider."""
    provider_name: str
    status: DataStatus
    threat_score: Optional[ThreatScore] = None
    reputation: Optional[ReputationData] = None
    evidence: List[EvidenceItem] = field(default_factory=list)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


@dataclass(frozen=True)
class EvidenceSummary:
    """Summary metrics of aggregated evidence items by severity."""
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


@dataclass(frozen=True)
class IPIntelResult:
    """Aggregated normalized threat intelligence, network, and evidence correlation result."""
    investigation_id: str
    target_ip: str
    timestamp: str
    is_mock: bool = False
    overall_threat_score: ThreatScore = field(
        default_factory=lambda: ThreatScore(0, ThreatLevel.UNKNOWN, 0, DataStatus.UNKNOWN)
    )
    rdap: RDAPData = field(default_factory=RDAPData)
    asn_data: ASNData = field(default_factory=ASNData)
    geoip: GeoIPData = field(default_factory=GeoIPData)
    dns: DNSData = field(default_factory=DNSData)
    waf_context: Optional[WAFContext] = None
    provider_results: Dict[str, ProviderResult] = field(default_factory=dict)
    aggregated_evidence: List[EvidenceItem] = field(default_factory=list)
    evidence_summary: EvidenceSummary = field(default_factory=EvidenceSummary)
    has_conflicting_evidence: bool = False
    conflict_explanation: Optional[str] = None
    is_private_ip: bool = False
    is_loopback_ip: bool = False
    summary_notes: str = ""

    # Status shortcuts
    @property
    def rdap_status(self) -> DataStatus:
        return self.rdap.status

    @property
    def asn_status(self) -> DataStatus:
        return self.asn_data.status

    @property
    def geoip_status(self) -> DataStatus:
        return self.geoip.status

    @property
    def dns_status(self) -> DataStatus:
        return self.dns.status
