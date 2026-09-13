"""Passive RDAP (Registration Data Access Protocol) provider."""

import datetime
import logging
import time
from typing import Any, Dict, Optional

import requests

from ip_sentinel.core.cache import CacheManager
from ip_sentinel.models.threat_intel import DataStatus, RDAPData

logger = logging.getLogger("ip_sentinel.providers.rdap")


class RDAPProvider:
    """Passive RDAP query client retrieving IP registration and allocation data."""

    BOOTSTRAP_URL = "https://rdap-bootstrap.arin.net/bootstrap/ip/"
    FALLBACK_URL = "https://rdap.db.ripe.net/ip/"

    def __init__(self, timeout: float = 4.0, cache_ttl: int = 3600):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache = CacheManager()

    def query_rdap(self, target_ip: str) -> RDAPData:
        """Query RDAP registration telemetry for target IP.
        
        Args:
            target_ip: Sanitized IPv4 or IPv6 address string.
            
        Returns:
            Normalized RDAPData container.
        """
        cache_key = f"rdap_{target_ip}"
        cached = self.cache.get(cache_key)
        if cached and isinstance(cached, dict):
            logger.info(f"Returning cached RDAP data for {target_ip}")
            return self._dict_to_rdap_data(cached)

        url = f"{self.BOOTSTRAP_URL}{target_ip}"
        headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "IP-Sentinel-AI/1.0"}

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                logger.warning(f"RDAP rate limit hit for {target_ip}")
                return RDAPData(
                    status=DataStatus.ERROR,
                    ip_address=target_ip,
                    lookup_timestamp=now_str,
                    error_message="RDAP Rate Limit Exceeded (HTTP 429)",
                )

            if resp.status_code in (404, 400):
                # Try fallback RIPE RDAP endpoint
                resp = requests.get(f"{self.FALLBACK_URL}{target_ip}", headers=headers, timeout=self.timeout)

            if resp.status_code != 200:
                logger.info(f"RDAP lookup returned status {resp.status_code} for {target_ip}")
                return RDAPData(
                    status=DataStatus.UNAVAILABLE,
                    ip_address=target_ip,
                    lookup_timestamp=now_str,
                    error_message=f"RDAP record not found (HTTP {resp.status_code})",
                )

            data = resp.json()
            rdap_res = self._parse_rdap_json(target_ip, data, now_str)

            # Persist to cache
            self.cache.set(cache_key, self._rdap_data_to_dict(rdap_res), ttl_seconds=self.cache_ttl)
            return rdap_res

        except requests.exceptions.Timeout:
            logger.warning(f"RDAP request timed out after {self.timeout}s for {target_ip}")
            return RDAPData(
                status=DataStatus.ERROR,
                ip_address=target_ip,
                lookup_timestamp=now_str,
                error_message=f"RDAP request timed out ({self.timeout}s)",
            )
        except Exception as err:
            logger.error(f"RDAP lookup error for {target_ip}: {err}")
            return RDAPData(
                status=DataStatus.ERROR,
                ip_address=target_ip,
                lookup_timestamp=now_str,
                error_message=f"RDAP resolution exception: {err}",
            )

    def _parse_rdap_json(self, target_ip: str, data: Dict[str, Any], timestamp: str) -> RDAPData:
        network_name = data.get("name")
        start_addr = data.get("startAddress")
        end_addr = data.get("endAddress")
        country = data.get("country")
        ip_version = 6 if ":" in target_ip else 4

        # Extract CIDR
        cidr_str = None
        cidrs = data.get("cidr0_cidrs")
        if cidrs and isinstance(cidrs, list) and len(cidrs) > 0:
            c_first = cidrs[0]
            if isinstance(c_first, dict):
                v = c_first.get("v4prefix") or c_first.get("v6prefix")
                length = c_first.get("length")
                if v and length:
                    cidr_str = f"{v}/{length}"

        if not cidr_str and start_addr and end_addr:
            cidr_str = f"{start_addr} - {end_addr}"

        # Extract Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
        port43 = data.get("port43", "")
        registry = "UNKNOWN"
        if "arin" in port43.lower() or "arin" in str(data).lower():
            registry = "ARIN"
        elif "ripe" in port43.lower() or "ripe" in str(data).lower():
            registry = "RIPE"
        elif "apnic" in port43.lower() or "apnic" in str(data).lower():
            registry = "APNIC"
        elif "lacnic" in port43.lower() or "lacnic" in str(data).lower():
            registry = "LACNIC"
        elif "afrinic" in port43.lower() or "afrinic" in str(data).lower():
            registry = "AFRINIC"

        # Extract Entities (Org, Abuse, Admin)
        org_name = None
        abuse_contact = None
        admin_contact = None

        entities = data.get("entities", [])
        if isinstance(entities, list):
            for ent in entities:
                roles = ent.get("roles", [])
                vcards = ent.get("vcardArray", [])
                fn = self._extract_vcard_fn(vcards)

                if "registrant" in roles or "sponsor" in roles or "owner" in roles:
                    if fn and not org_name:
                        org_name = fn

                if "abuse" in roles:
                    abuse_email = self._extract_vcard_email(vcards) or fn
                    if abuse_email:
                        abuse_contact = abuse_email

                if "administrative" in roles:
                    admin_contact = fn

        return RDAPData(
            status=DataStatus.AVAILABLE,
            ip_address=target_ip,
            ip_version=ip_version,
            network_name=network_name,
            cidr=cidr_str,
            start_address=start_addr,
            end_address=end_addr,
            organization=org_name or network_name,
            country=country,
            admin_contact=admin_contact,
            abuse_contact=abuse_contact,
            registry=registry,
            lookup_timestamp=timestamp,
            raw_payload={},
            error_message=None,
        )

    def _extract_vcard_fn(self, vcard_array: Any) -> Optional[str]:
        if not vcard_array or not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return None
        items = vcard_array[1]
        for item in items:
            if isinstance(item, list) and len(item) >= 4:
                if item[0] == "fn":
                    return item[3]
        return None

    def _extract_vcard_email(self, vcard_array: Any) -> Optional[str]:
        if not vcard_array or not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return None
        items = vcard_array[1]
        for item in items:
            if isinstance(item, list) and len(item) >= 4:
                if item[0] == "email":
                    return item[3]
        return None

    def _rdap_data_to_dict(self, obj: RDAPData) -> Dict[str, Any]:
        return {
            "status": obj.status.value,
            "ip_address": obj.ip_address,
            "ip_version": obj.ip_version,
            "network_name": obj.network_name,
            "cidr": obj.cidr,
            "start_address": obj.start_address,
            "end_address": obj.end_address,
            "organization": obj.organization,
            "country": obj.country,
            "admin_contact": obj.admin_contact,
            "abuse_contact": obj.abuse_contact,
            "registry": obj.registry,
            "lookup_timestamp": obj.lookup_timestamp,
            "error_message": obj.error_message,
        }

    def _dict_to_rdap_data(self, d: Dict[str, Any]) -> RDAPData:
        return RDAPData(
            status=DataStatus(d.get("status", DataStatus.AVAILABLE.value)),
            ip_address=d.get("ip_address"),
            ip_version=d.get("ip_version"),
            network_name=d.get("network_name"),
            cidr=d.get("cidr"),
            start_address=d.get("start_address"),
            end_address=d.get("end_address"),
            organization=d.get("organization"),
            country=d.get("country"),
            admin_contact=d.get("admin_contact"),
            abuse_contact=d.get("abuse_contact"),
            registry=d.get("registry"),
            lookup_timestamp=d.get("lookup_timestamp"),
            error_message=d.get("error_message"),
        )
