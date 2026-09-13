"""Vendor-specific WAF parser stubs.

Prepares architecture for AWS WAF, Cloudflare, ModSecurity, and Akamai log ingestion.
Inherits from BaseWAFParser and utilizes JSONWAFParser/CSVWAFParser normalizers.
"""

from typing import List
from ip_sentinel.models.waf_event import WAFEvent
from ip_sentinel.parsers.json_parser import JSONWAFParser


class AWSWAFParser(JSONWAFParser):
    """AWS WAF JSON log parser stub."""
    pass


class CloudflareWAFParser(JSONWAFParser):
    """Cloudflare WAF log parser stub."""
    pass


class ModSecurityWAFParser(JSONWAFParser):
    """ModSecurity SecAuditLog parser stub."""
    pass


class AKAMAIWAFParser(JSONWAFParser):
    """Akamai Kona Site Defender log parser stub."""
    pass
