"""Passive GeoIP (Geolocation) and ASN telemetry provider."""

import datetime
import logging
import re
from typing import Any, Dict, Optional, Tuple

import requests

from ip_sentinel.core.cache import CacheManager
from ip_sentinel.models.threat_intel import ASNData, DataStatus, GeoIPData

logger = logging.getLogger("ip_sentinel.providers.geoip")

MANDATORY_GEOIP_DISCLAIMER = (
    "GeoIP information represents approximate network geolocation and does not identify the physical location of an attacker."
)


class GeoIPProvider:
    """Passive HTTPS GeoIP and ASN telemetry provider."""

    GEO_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    def __init__(self, timeout: float = 3.0, cache_ttl: int = 3600):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache = CacheManager()

    def query_geoip_and_asn(self, target_ip: str) -> Tuple[GeoIPData, ASNData]:
        """Query GeoIP and ASN telemetry for given IP address.
        
        Returns:
            Tuple of (GeoIPData, ASNData)
        """
        cache_key = f"geoip_{target_ip}"
        cached = self.cache.get(cache_key)
        if cached and isinstance(cached, dict):
            logger.info(f"Returning cached GeoIP/ASN data for {target_ip}")
            return self._dict_to_geoip_data(cached["geoip"]), self._dict_to_asn_data(cached["asn"])

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            url = self.GEO_URL.format(ip=target_ip)
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code != 200:
                logger.warning(f"GeoIP endpoint returned status {resp.status_code} for {target_ip}")
                err_geo = GeoIPData(
                    status=DataStatus.UNAVAILABLE,
                    disclaimer=MANDATORY_GEOIP_DISCLAIMER,
                    error_message=f"GeoIP endpoint HTTP {resp.status_code}",
                )
                err_asn = ASNData(
                    status=DataStatus.UNAVAILABLE,
                    timestamp=now_str,
                    error_message=f"ASN lookup HTTP {resp.status_code}",
                )
                return err_geo, err_asn

            data = resp.json()
            if data.get("status") == "fail":
                msg = data.get("message", "Unknown query failure")
                logger.info(f"GeoIP lookup failed for {target_ip}: {msg}")
                err_geo = GeoIPData(
                    status=DataStatus.UNAVAILABLE,
                    disclaimer=MANDATORY_GEOIP_DISCLAIMER,
                    error_message=f"GeoIP failed: {msg}",
                )
                err_asn = ASNData(
                    status=DataStatus.UNAVAILABLE,
                    timestamp=now_str,
                    error_message=f"ASN failed: {msg}",
                )
                return err_geo, err_asn

            # Parse GeoIP & ASN payload
            country_code = data.get("countryCode")
            country_name = data.get("country")
            region = data.get("regionName")
            city = data.get("city")
            timezone = data.get("timezone")
            isp = data.get("isp")
            org = data.get("org")
            lat = data.get("lat")
            lon = data.get("lon")
            as_string = data.get("as", "")  # Format: "AS13335 Cloudflare, Inc."

            # Parse ASN number and org from "as" field
            asn_num = None
            asn_org = org or isp
            if as_string:
                match = re.match(r"AS(\d+)\s*(.*)", as_string)
                if match:
                    asn_num = int(match.group(1))
                    if match.group(2):
                        asn_org = match.group(2)

            geoip_res = GeoIPData(
                status=DataStatus.AVAILABLE,
                country_code=country_code,
                country_name=country_name,
                region=region,
                city=city,
                timezone=timezone,
                asn=asn_num,
                asn_org=asn_org,
                isp=isp,
                latitude=float(lat) if lat is not None else None,
                longitude=float(lon) if lon is not None else None,
                disclaimer=MANDATORY_GEOIP_DISCLAIMER,
                error_message=None,
            )

            asn_res = ASNData(
                status=DataStatus.AVAILABLE,
                asn=asn_num,
                asn_org=asn_org,
                country=country_code,
                registry="RIR",
                source="GeoIP ASN Feed",
                timestamp=now_str,
                error_message=None,
            )

            # Store in cache
            self.cache.set(
                cache_key,
                {
                    "geoip": self._geoip_data_to_dict(geoip_res),
                    "asn": self._asn_data_to_dict(asn_res),
                },
                ttl_seconds=self.cache_ttl,
            )
            return geoip_res, asn_res

        except requests.exceptions.Timeout:
            logger.warning(f"GeoIP request timed out for {target_ip}")
            return (
                GeoIPData(
                    status=DataStatus.ERROR,
                    disclaimer=MANDATORY_GEOIP_DISCLAIMER,
                    error_message=f"GeoIP request timed out ({self.timeout}s)",
                ),
                ASNData(
                    status=DataStatus.ERROR,
                    timestamp=now_str,
                    error_message=f"ASN request timed out ({self.timeout}s)",
                ),
            )
        except Exception as err:
            logger.error(f"GeoIP resolution error for {target_ip}: {err}")
            return (
                GeoIPData(
                    status=DataStatus.ERROR,
                    disclaimer=MANDATORY_GEOIP_DISCLAIMER,
                    error_message=f"GeoIP exception: {err}",
                ),
                ASNData(
                    status=DataStatus.ERROR,
                    timestamp=now_str,
                    error_message=f"ASN exception: {err}",
                ),
            )

    def _geoip_data_to_dict(self, g: GeoIPData) -> Dict[str, Any]:
        return {
            "status": g.status.value,
            "country_code": g.country_code,
            "country_name": g.country_name,
            "region": g.region,
            "city": g.city,
            "timezone": g.timezone,
            "asn": g.asn,
            "asn_org": g.asn_org,
            "isp": g.isp,
            "latitude": g.latitude,
            "longitude": g.longitude,
            "disclaimer": g.disclaimer,
            "error_message": g.error_message,
        }

    def _asn_data_to_dict(self, a: ASNData) -> Dict[str, Any]:
        return {
            "status": a.status.value,
            "asn": a.asn,
            "asn_org": a.asn_org,
            "country": a.country,
            "registry": a.registry,
            "source": a.source,
            "timestamp": a.timestamp,
            "error_message": a.error_message,
        }

    def _dict_to_geoip_data(self, d: Dict[str, Any]) -> GeoIPData:
        return GeoIPData(
            status=DataStatus(d.get("status", DataStatus.AVAILABLE.value)),
            country_code=d.get("country_code"),
            country_name=d.get("country_name"),
            region=d.get("region"),
            city=d.get("city"),
            timezone=d.get("timezone"),
            asn=d.get("asn"),
            asn_org=d.get("asn_org"),
            isp=d.get("isp"),
            latitude=d.get("latitude"),
            longitude=d.get("longitude"),
            disclaimer=d.get("disclaimer", MANDATORY_GEOIP_DISCLAIMER),
            error_message=d.get("error_message"),
        )

    def _dict_to_asn_data(self, d: Dict[str, Any]) -> ASNData:
        return ASNData(
            status=DataStatus(d.get("status", DataStatus.AVAILABLE.value)),
            asn=d.get("asn"),
            asn_org=d.get("asn_org"),
            country=d.get("country"),
            registry=d.get("registry"),
            source=d.get("source"),
            timestamp=d.get("timestamp"),
            error_message=d.get("error_message"),
        )
