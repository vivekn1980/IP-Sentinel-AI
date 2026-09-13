"""Abstract Base Class for WAF Log Parsers."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ip_sentinel.core.ip_utils import sanitize_ip, is_valid_ip
from ip_sentinel.models.waf_event import WAFEvent

logger = logging.getLogger("ip_sentinel.parsers.base")


class BaseWAFParser(ABC):
    """Abstract base class for ingesting and normalizing WAF log events."""

    @abstractmethod
    def parse_file(self, file_path: str) -> List[WAFEvent]:
        """Parse WAF events from a file on disk."""
        pass

    @abstractmethod
    def parse_content(self, content_str: str) -> List[WAFEvent]:
        """Parse WAF events from a string buffer."""
        pass

    def _normalize_dict(self, row: Dict[str, Any]) -> WAFEvent:
        """Map raw dictionary keys to normalized WAFEvent dataclass fields."""
        # Convert all keys to lowercase for flexible matching
        lc_row = {str(k).lower().strip(): v for k, v in row.items() if k is not None}

        # IP extraction with aliases
        raw_ip = (
            lc_row.get("source_ip")
            or lc_row.get("client_ip")
            or lc_row.get("ip")
            or lc_row.get("remote_addr")
            or lc_row.get("src_ip")
            or lc_row.get("c_ip")
            or lc_row.get("origin_ip")
            or "0.0.0.0"
        )
        source_ip = sanitize_ip(str(raw_ip))
        if not is_valid_ip(source_ip):
            source_ip = "0.0.0.0"

        # Timestamp
        timestamp = (
            lc_row.get("timestamp")
            or lc_row.get("time")
            or lc_row.get("date")
            or lc_row.get("@timestamp")
            or lc_row.get("datetime")
        )
        timestamp_str = str(timestamp).strip() if timestamp else None

        # HTTP Method
        http_method = (
            lc_row.get("http_method")
            or lc_row.get("method")
            or lc_row.get("request_method")
            or "UNKNOWN"
        )
        http_method_str = str(http_method).strip().upper() if http_method else "UNKNOWN"

        # URI Path
        uri_path = (
            lc_row.get("uri_path")
            or lc_row.get("uri")
            or lc_row.get("path")
            or lc_row.get("request_uri")
            or lc_row.get("url")
            or "UNKNOWN"
        )
        uri_path_str = str(uri_path).strip() if uri_path else "UNKNOWN"

        # User Agent
        user_agent = (
            lc_row.get("user_agent")
            or lc_row.get("ua")
            or lc_row.get("http_user_agent")
            or lc_row.get("client_ua")
            or "UNKNOWN"
        )
        user_agent_str = str(user_agent).strip() if user_agent else "UNKNOWN"

        # Status Code
        status_code_raw = (
            lc_row.get("status_code")
            or lc_row.get("status")
            or lc_row.get("response_code")
            or lc_row.get("http_status")
        )
        status_code: Optional[int] = None
        if status_code_raw is not None:
            try:
                status_code = int(status_code_raw)
            except (ValueError, TypeError):
                status_code = None

        # WAF Rule & Action
        waf_rule = (
            lc_row.get("waf_rule")
            or lc_row.get("rule")
            or lc_row.get("rule_id")
            or lc_row.get("matched_rule")
            or "UNKNOWN"
        )
        waf_action = (
            lc_row.get("waf_action")
            or lc_row.get("action")
            or lc_row.get("disposition")
            or "UNKNOWN"
        )

        # Other fields
        request_id = str(lc_row.get("request_id") or lc_row.get("id") or "UNKNOWN")
        host = str(lc_row.get("host") or lc_row.get("hostname") or "UNKNOWN")
        country = str(lc_row.get("country") or lc_row.get("geo_country") or "UNKNOWN")
        
        response_size_raw = lc_row.get("response_size") or lc_row.get("bytes") or lc_row.get("body_bytes_sent")
        response_size: Optional[int] = None
        if response_size_raw is not None:
            try:
                response_size = int(response_size_raw)
            except (ValueError, TypeError):
                response_size = None

        request_type = str(lc_row.get("request_type") or "UNKNOWN")
        attack_vector = str(lc_row.get("attack_vector") or lc_row.get("vector") or "UNKNOWN")

        return WAFEvent(
            timestamp=timestamp_str,
            source_ip=source_ip,
            http_method=http_method_str,
            uri_path=uri_path_str,
            user_agent=user_agent_str,
            status_code=status_code,
            waf_rule=str(waf_rule).strip() if waf_rule else "UNKNOWN",
            waf_action=str(waf_action).strip().upper() if waf_action else "UNKNOWN",
            request_id=request_id,
            host=host,
            country=country,
            response_size=response_size,
            request_type=request_type,
            attack_vector=attack_vector,
            additional_metadata=dict(lc_row),
        )
