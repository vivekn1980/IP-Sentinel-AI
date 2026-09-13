"""Normalized threat intelligence and network data transfer objects (DTOs).

Supports Phase 2 real passive network intelligence: RDAP, ASN, GeoIP, and DNS.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DataStatus(Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNKNOWN = "UNKNOWN"


class ThreatLevel(Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ThreatScore:
    """Normalized threat score metric scaled 0 to 100."""
    score: int  # 0 to 100
    level: ThreatLevel
    confidence: int = 100  # 0 to 100 percentage
    status: DataStatus = DataStatus.AVAILABLE


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
    registry: Optional[str] = None  # ARIN, RIPE, APNIC, LACNIC, AFRINIC
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
    hostname: Optional[str] = None  # Primary reverse PTR
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
    total_reports: int = 0
    distinct_reporters: int = 0
    last_reported_at: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass(frozen=True)
class EvidenceItem:
    """Structured evidence item supporting threat assessment."""
    category: str
    description: str
    source: str
    timestamp: Optional[str] = None
    severity: str = "INFO"


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
class IPIntelResult:
    """Aggregated normalized threat intelligence and network investigation result."""
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
    provider_results: Dict[str, ProviderResult] = field(default_factory=dict)
    aggregated_evidence: List[EvidenceItem] = field(default_factory=list)
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
