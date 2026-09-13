"""Safe DNS Resolution Service querying PTR, A, AAAA, MX, NS, TXT, and CNAME records."""

import logging
from typing import List, Optional

import dns.resolver
import dns.reversename

from ip_sentinel.models.threat_intel import DNSData, DataStatus

logger = logging.getLogger("ip_sentinel.services.dns")


class DNSService:
    """Safe DNS resolution client executing non-intrusive standard record lookups."""

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    def resolve_all_records(self, ip_str: str) -> DNSData:
        """Perform comprehensive DNS resolution for target IP.
        
        Args:
            ip_str: Target IP address string.
            
        Returns:
            Normalized DNSData object.
        """
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        ptr_records = self._query_ptr(resolver, ip_str)
        primary_host = ptr_records[0] if ptr_records else None

        a_records = []
        aaaa_records = []
        mx_records = []
        ns_records = []
        txt_records = []
        cname_records = []

        # If reverse PTR resolved to a domain name, query records for that hostname
        if primary_host:
            a_records = self._query_record_type(resolver, primary_host, "A")
            aaaa_records = self._query_record_type(resolver, primary_host, "AAAA")
            mx_records = self._query_record_type(resolver, primary_host, "MX")
            ns_records = self._query_record_type(resolver, primary_host, "NS")
            txt_records = self._query_record_type(resolver, primary_host, "TXT")
            cname_records = self._query_record_type(resolver, primary_host, "CNAME")

        has_data = any([ptr_records, a_records, aaaa_records, mx_records, ns_records, txt_records, cname_records])
        status = DataStatus.AVAILABLE if has_data else DataStatus.UNAVAILABLE

        return DNSData(
            status=status,
            hostname=primary_host,
            ptr_records=ptr_records,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            cname_records=cname_records,
            error_message=None if has_data else "No DNS records resolved for IP or hostname.",
        )

    def _query_ptr(self, resolver: dns.resolver.Resolver, ip_str: str) -> List[str]:
        results = []
        try:
            rev_name = dns.reversename.from_address(ip_str)
            answers = resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                results.append(str(rdata.target).rstrip("."))
        except Exception as err:
            logger.debug(f"PTR lookup failed for {ip_str}: {err}")
        return results

    def _query_record_type(self, resolver: dns.resolver.Resolver, hostname: str, rtype: str) -> List[str]:
        results = []
        try:
            answers = resolver.resolve(hostname, rtype)
            for rdata in answers:
                if rtype == "MX":
                    results.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif rtype in ("A", "AAAA", "NS", "CNAME"):
                    results.append(str(rdata).rstrip("."))
                elif rtype == "TXT":
                    results.append(str(rdata).strip('"'))
                else:
                    results.append(str(rdata))
        except Exception as err:
            logger.debug(f"DNS {rtype} query failed for {hostname}: {err}")
        return results
