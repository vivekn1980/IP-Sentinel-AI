"""Data models for Origin IP and CDN discovery engine."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CDNCheckResult:
    """CDN identification result for an IP address."""
    ip: str
    is_cdn: bool
    provider: Optional[str] = None
    matched_cidr: Optional[str] = None


@dataclass
class SSLCertificateDetails:
    """Detailed metadata and validity status of an SSL/TLS certificate."""
    target: str
    port: int = 443
    common_name: str = ""
    sans: List[str] = field(default_factory=list)
    issuer_org: str = ""
    issuer_cn: str = ""
    valid_from: str = ""
    valid_to: str = ""
    days_remaining: int = 0
    status: str = "VALID"  # 'VALID', 'EXPIRING_SOON', 'EXPIRED', 'ERROR'
    serial_number: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    sha256_fingerprint: str = ""
    error: Optional[str] = None


@dataclass
class HistoricalDNSRecord:
    """Historical passive DNS record for a domain."""
    domain: str
    ip: str
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""  # e.g., 'AlienVault OTX', 'HackerTarget'
    is_cdn: bool = False
    cdn_provider: Optional[str] = None


@dataclass
class PortBanner:
    """Port scan and service banner details."""
    port: int
    service_name: str  # e.g. 'HTTP', 'HTTPS', 'SSH', 'FTP', 'MySQL', 'RDP'
    state: str = "OPEN"  # 'OPEN', 'CLOSED', 'FILTERED'
    banner: str = ""
    is_ssl: bool = False


@dataclass
class PortScanResult:
    """Full port scanning and banner grabbing result for an IP."""
    ip: str
    open_ports: List[PortBanner] = field(default_factory=list)
    scanned_ports: List[int] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class OriginCandidate:
    """Candidate origin IP discovered via subdomains, CT logs, or email headers."""
    ip: str
    discovery_source: str  # e.g., 'Subdomain Scan (direct.example.com)', 'CT Logs (crt.sh)', 'Email Header'
    validated: bool = False
    http_status: Optional[str] = None
    response_snippet: Optional[str] = None
    error_message: Optional[str] = None
    cert_details: Optional[SSLCertificateDetails] = None
    port_scan: Optional[PortScanResult] = None


@dataclass
class FaviconHashResult:
    """MMH3 hash and Shodan search syntax for a website favicon."""
    favicon_url: str
    http_status: int = 0
    mmh3_hash: Optional[int] = None
    shodan_query: Optional[str] = None
    error: Optional[str] = None


@dataclass
class EmailHeaderAnalysisResult:
    """Extracted IP addresses from raw email headers."""
    raw_header_length: int = 0
    extracted_ips: List[str] = field(default_factory=list)
    candidate_origin_ips: List[str] = field(default_factory=list)


@dataclass
class OriginDiscoveryResult:
    """Complete summary of Origin IP & CDN discovery for a target URL/domain."""
    target_url: str
    target_domain: str
    resolved_ips: List[str] = field(default_factory=list)
    cdn_ips: List[CDNCheckResult] = field(default_factory=list)
    candidate_origins: List[OriginCandidate] = field(default_factory=list)
    validated_origins: List[OriginCandidate] = field(default_factory=list)
    favicon_result: Optional[FaviconHashResult] = None
    email_analysis: Optional[EmailHeaderAnalysisResult] = None
    historical_dns: List[HistoricalDNSRecord] = field(default_factory=list)
    is_behind_cdn: bool = False
    execution_time_seconds: float = 0.0
