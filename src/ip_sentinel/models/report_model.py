"""Report configuration and report metadata data transfer objects."""

from dataclasses import dataclass, field
from typing import List, Optional
from ip_sentinel.models.threat_intel import IPIntelResult


@dataclass(frozen=True)
class ReportMetadata:
    """Metadata attached to generated investigation reports."""
    title: str = "WAF IP Threat Intelligence Report"
    app_version: str = "5.0.0-phase5"
    generated_at: str = ""
    author: str = "Vivek Nigam (IP Sentinel AI Engine)"
    organization: str = "Security Operations Center"


@dataclass(frozen=True)
class ReportData:
    """Complete dataset passed to HTML/PDF report generators."""
    result: IPIntelResult
    metadata: ReportMetadata
    notes: Optional[str] = None
    executive_summary: str = ""
