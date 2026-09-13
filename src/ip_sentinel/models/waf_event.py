"""Normalized WAF Event data model DTO.

Represents a single Web Application Firewall (WAF) HTTP request log entry.
Missing fields default to "UNKNOWN" or None.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class WAFEvent:
    """Normalized single Web Application Firewall (WAF) event entry."""

    timestamp: Optional[str] = None
    source_ip: str = "0.0.0.0"
    http_method: str = "UNKNOWN"
    uri_path: str = "UNKNOWN"
    user_agent: str = "UNKNOWN"
    status_code: Optional[int] = None
    waf_rule: str = "UNKNOWN"
    waf_action: str = "UNKNOWN"  # ALLOW, BLOCK, LOG, CHALLENGE, etc.
    request_id: str = "UNKNOWN"
    host: str = "UNKNOWN"
    country: str = "UNKNOWN"
    response_size: Optional[int] = None
    request_type: str = "UNKNOWN"
    attack_vector: str = "UNKNOWN"
    additional_metadata: Dict[str, Any] = field(default_factory=dict)
