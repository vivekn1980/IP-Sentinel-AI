"""IP address validation, classification, and sanitization utilities.

Uses standard library `ipaddress` module to prevent shell injection, malformed inputs,
and unsafe execution vectors.
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional, Tuple, Union


@dataclass(frozen=True)
class IPClassification:
    """Classification metadata for an IP address."""
    raw_input: str
    normalized_ip: str
    version: int  # 4 or 6
    is_valid: bool
    is_private: bool
    is_loopback: bool
    is_reserved: bool
    is_multicast: bool
    is_global: bool
    is_link_local: bool
    error_message: Optional[str] = None


def validate_and_classify_ip(ip_str: str) -> IPClassification:
    """Validate, sanitize, and classify an IP address string.
    
    Args:
        ip_str: Input IP address string from user or input stream.
        
    Returns:
        IPClassification object containing safety and network properties.
    """
    if not ip_str or not isinstance(ip_str, str):
        return IPClassification(
            raw_input=str(ip_str),
            normalized_ip="",
            version=0,
            is_valid=False,
            is_private=False,
            is_loopback=False,
            is_reserved=False,
            is_multicast=False,
            is_global=False,
            is_link_local=False,
            error_message="IP address input cannot be empty.",
        )

    sanitized = ip_str.strip()

    try:
        ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = ipaddress.ip_address(sanitized)
        return IPClassification(
            raw_input=ip_str,
            normalized_ip=str(ip_obj),
            version=ip_obj.version,
            is_valid=True,
            is_private=ip_obj.is_private,
            is_loopback=ip_obj.is_loopback,
            is_reserved=ip_obj.is_reserved,
            is_multicast=ip_obj.is_multicast,
            is_global=ip_obj.is_global,
            is_link_local=ip_obj.is_link_local,
            error_message=None,
        )
    except ValueError as err:
        return IPClassification(
            raw_input=ip_str,
            normalized_ip="",
            version=0,
            is_valid=False,
            is_private=False,
            is_loopback=False,
            is_reserved=False,
            is_multicast=False,
            is_global=False,
            is_link_local=False,
            error_message=f"Invalid IP address format: {err}",
        )


def validate_cidr(cidr_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate a CIDR network range string.
    
    Returns:
        Tuple of (is_valid, normalized_cidr_or_none, error_message_or_none)
    """
    if not cidr_str or not isinstance(cidr_str, str):
        return False, None, "CIDR input cannot be empty."

    sanitized = cidr_str.strip()
    try:
        net = ipaddress.ip_network(sanitized, strict=False)
        return True, str(net), None
    except ValueError as err:
        return False, None, f"Invalid CIDR network format: {err}"


def sanitize_ip(ip_str: str) -> str:
    """Sanitize and clean raw IP string input."""
    if not ip_str or not isinstance(ip_str, str):
        return ""
    cleaned = ip_str.strip().strip("'\"").strip()
    return cleaned


def is_valid_ip(ip_str: str) -> bool:
    """Quick boolean check if input is a valid IPv4 or IPv6 address."""
    classification = validate_and_classify_ip(ip_str)
    return classification.is_valid
