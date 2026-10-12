"""Origin IP Discovery & CDN Bypass Service."""

import base64
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple, Dict, Set

from ip_sentinel.models.origin_finder import (
    CDNCheckResult,
    EmailHeaderAnalysisResult,
    FaviconHashResult,
    HistoricalDNSRecord,
    OriginCandidate,
    OriginDiscoveryResult,
    PortBanner,
    PortScanResult,
    SSLCertificateDetails,
)

logger = logging.getLogger("ip_sentinel.services.origin_ip")

# Known public CIDR ranges for popular CDNs
CDN_CIDRS: Dict[str, List[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "13.249.0.0/16",
        "52.84.0.0/15", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18",
        "54.240.128.0/18", "64.252.64.0/18", "70.132.0.0/18", "99.84.0.0/16",
        "204.246.164.0/22", "204.246.168.0/22", "205.251.192.0/19", "216.137.32.0/19"
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
        "2a04:4e40::/32", "2a04:4e42::/32"
    ],
    "Imperva / Incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
        "185.11.124.0/22", "192.230.64.0/18", "107.154.0.0/16", "45.55.0.0/16"
    ],
    "Tata Communications (BitGravity CDN)": [
        "64.185.160.0/19", "209.234.240.0/20", "206.51.224.0/19", "121.240.0.0/14",
        "115.112.0.0/14", "180.149.32.0/19"
    ],
    "Microsoft Azure CDN": [
        "13.107.246.0/24", "13.107.213.0/24", "150.171.64.0/18", "52.244.0.0/16"
    ],
    "Google Cloud CDN": [
        "34.96.0.0/12", "34.112.0.0/12", "35.186.192.0/18"
    ],
    "Edgio / Limelight": [
        "68.142.64.0/18", "69.28.128.0/18", "178.79.192.0/18"
    ],
    "CDNetworks": [
        "14.0.32.0/19", "110.234.0.0/16"
    ],
    "Sucuri": [
        "192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22"
    ],
    "BunnyCDN": [
        "185.246.208.0/22", "185.180.12.0/22", "169.150.192.0/18"
    ],
    "Akamai": [
        "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"
    ]
}

# CNAME keywords identifying CDN vendor edge proxies
CDN_CNAME_KEYWORDS: Dict[str, str] = {
    "cloudflare.net": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "azureedge.net": "Microsoft Azure CDN",
    "azurefd.net": "Microsoft Azure Front Door",
    "incapdns.net": "Imperva / Incapsula",
    "sucuri.net": "Sucuri",
    "b-cdn.net": "BunnyCDN",
    "hwcdn.net": "Highwinds / StackPath",
    "llnwd.net": "Edgio / Limelight",
    "bitgravity.com": "Tata Communications (BitGravity CDN)",
}

# Common subdomains that frequently bypass CDN proxies
ORIGIN_SUBDOMAINS = [
    "direct", "origin", "backend", "server", "main", "dev", "staging", "test",
    "mail", "cpanel", "webmail", "smtp", "pop", "ftp", "vpn", "m", "old",
    "admin", "api", "auth", "portal", "db", "mysql", "internal", "app"
]

# Standard ports scanned for service banners
DEFAULT_SCAN_PORTS = [21, 22, 80, 443, 3306, 3389, 8080, 8443]
PORT_SERVICE_MAP: Dict[int, Tuple[str, bool]] = {
    21: ("FTP", False),
    22: ("SSH", False),
    80: ("HTTP", False),
    443: ("HTTPS", True),
    3306: ("MySQL", False),
    3389: ("RDP", False),
    8080: ("HTTP-Alt", False),
    8443: ("HTTPS-Alt", True),
}


def mmh3_hash_bytes(data: bytes) -> int:
    """Pure-Python implementation of MurmurHash3 32-bit (x86) algorithm."""
    try:
        import mmh3
        return mmh3.hash(data)
    except ImportError:
        pass

    # Pure Python Murmur3 32-bit fallback
    length = len(data)
    seed = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    h1 = seed
    rounded_len = length & ~0x3

    for i in range(0, rounded_len, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | ((data[i + 2] & 0xff) << 16) | ((data[i + 3] & 0xff) << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    tail_len = length & 3
    if tail_len == 3:
        k1 ^= (data[rounded_len + 2] & 0xff) << 16
    if tail_len >= 2:
        k1 ^= (data[rounded_len + 1] & 0xff) << 8
    if tail_len >= 1:
        k1 ^= (data[rounded_len] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)

    # Convert unsigned to signed 32-bit integer
    if h1 & 0x80000000:
        return -((~h1 + 1) & 0xffffffff)
    return h1


class OriginIPService:
    """Service discovering CDN IPs and candidate real Origin IPs for domains/URLs."""

    DEFAULT_SCAN_PORTS = DEFAULT_SCAN_PORTS
    PORT_SERVICE_MAP = PORT_SERVICE_MAP

    @staticmethod
    def extract_domain(input_url: str) -> str:
        """Extract clean hostname/domain from a URL or input string."""
        if not input_url:
            return ""
        clean_str = input_url.strip()
        if not clean_str.startswith(("http://", "https://")):
            clean_str = "https://" + clean_str
        try:
            parsed = urllib.parse.urlparse(clean_str)
            domain = parsed.hostname or parsed.path.split("/")[0]
            return domain.lower().strip()
        except Exception:
            return clean_str.split("/")[0].lower().strip()

    @staticmethod
    def resolve_cname(domain: str) -> Optional[str]:
        """Resolve CNAME target for a domain if present."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "CNAME")
            for r in answers:
                return str(r.target).rstrip(".")
        except Exception:
            pass
        return None

    @staticmethod
    def check_cdn(ip_str: str, domain: Optional[str] = None) -> CDNCheckResult:
        """Check if an IP address belongs to known public CDN CIDR ranges, CNAME, or PTR."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cdn_name, cidrs in CDN_CIDRS.items():
                for cidr in cidrs:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return CDNCheckResult(
                            ip=ip_str,
                            is_cdn=True,
                            provider=cdn_name,
                            matched_cidr=cidr,
                        )
        except ValueError:
            pass

        # Fallback 1: Domain CNAME inspection if domain was provided
        if domain:
            cname_target = OriginIPService.resolve_cname(domain)
            if cname_target:
                cname_lower = cname_target.lower()
                for kw, provider_name in CDN_CNAME_KEYWORDS.items():
                    if kw in cname_lower:
                        return CDNCheckResult(
                            ip=ip_str,
                            is_cdn=True,
                            provider=provider_name,
                            matched_cidr=f"CNAME ({cname_target})",
                        )

        # Fallback 2: Reverse DNS (PTR) hostname lookup check
        try:
            ptr_name, _, _ = socket.gethostbyaddr(ip_str)
            ptr_lower = ptr_name.lower()
            ptr_keywords = {
                "bitgravity": "Tata Communications (BitGravity CDN)",
                "tatacommunications": "Tata Communications (BitGravity CDN)",
                "akamaiedge": "Akamai",
                "akamai": "Akamai",
                "cloudfront": "AWS CloudFront",
                "cloudflare": "Cloudflare",
                "fastly": "Fastly",
                "incapsula": "Imperva / Incapsula",
                "imperva": "Imperva / Incapsula",
                "azureedge": "Microsoft Azure CDN",
                "limelight": "Edgio / Limelight",
                "llnwd": "Edgio / Limelight",
                "cdnetworks": "CDNetworks",
                "cdngslb": "CDNetworks",
                "bunny": "BunnyCDN",
                "b-cdn": "BunnyCDN",
                "sucuri": "Sucuri",
                "keycdn": "KeyCDN",
            }
            for kw, provider_name in ptr_keywords.items():
                if kw in ptr_lower:
                    return CDNCheckResult(
                        ip=ip_str,
                        is_cdn=True,
                        provider=provider_name,
                        matched_cidr=f"PTR Reverse DNS ({ptr_name})",
                    )
        except Exception:
            pass

        return CDNCheckResult(ip=ip_str, is_cdn=False)

    @staticmethod
    def resolve_dns(domain: str) -> List[str]:
        """Resolve IPv4 and IPv6 addresses for a domain."""
        ips = set()
        try:
            info = socket.getaddrinfo(domain, None)
            for item in info:
                ip = item[4][0]
                ips.add(ip)
        except socket.gaierror:
            pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain}: {e}")
        return list(ips)

    @staticmethod
    def fetch_crt_sh_subdomains(domain: str) -> List[str]:
        """Query crt.sh Certificate Transparency logs for subdomains."""
        subdomains: Set[str] = set()
        root_domain = ".".join(domain.split(".")[-2:]) if len(domain.split(".")) > 2 else domain
        url = f"https://crt.sh/?q=%.{root_domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Sentinel-AI/4.0.0"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub and not sub.startswith("*") and domain in sub:
                                subdomains.add(sub)
        except Exception as err:
            logger.debug(f"crt.sh CT log lookup skipped or failed for {domain}: {err}")
        return list(subdomains)

    @staticmethod
    def compute_favicon_hash(target_domain_or_url: str) -> FaviconHashResult:
        """Fetch target favicon.ico, compute base64 MurmurHash3, and generate Shodan search syntax."""
        domain = OriginIPService.extract_domain(target_domain_or_url)
        favicon_url = f"https://{domain}/favicon.ico"
        req = urllib.request.Request(favicon_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                if resp.status == 200:
                    content = resp.read()
                    b64_content = base64.encodebytes(content)
                    hash_val = mmh3_hash_bytes(b64_content)
                    shodan_q = f"http.favicon.hash:{hash_val}"
                    return FaviconHashResult(
                        favicon_url=favicon_url,
                        http_status=resp.status,
                        mmh3_hash=hash_val,
                        shodan_query=shodan_q,
                    )
                return FaviconHashResult(
                    favicon_url=favicon_url,
                    http_status=resp.status,
                    error=f"HTTP status {resp.status}",
                )
        except Exception as err:
            return FaviconHashResult(
                favicon_url=favicon_url,
                error=f"Unable to fetch favicon: {str(err)}",
            )

    @staticmethod
    def parse_email_headers(raw_headers: str) -> EmailHeaderAnalysisResult:
        """Extract IP addresses from raw email headers (Received: from ... [X.X.X.X])."""
        if not raw_headers:
            return EmailHeaderAnalysisResult()

        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        found_ips = ip_pattern.findall(raw_headers)
        
        unique_ips = []
        candidate_origins = []

        for ip in found_ips:
            if ip not in unique_ips:
                unique_ips.append(ip)
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        cdn_res = OriginIPService.check_cdn(ip)
                        if not cdn_res.is_cdn:
                            candidate_origins.append(ip)
                except ValueError:
                    pass

        return EmailHeaderAnalysisResult(
            raw_header_length=len(raw_headers),
            extracted_ips=unique_ips,
            candidate_origin_ips=candidate_origins,
        )

    @staticmethod
    def _probe_http(candidate_ip: str, target_domain: str, port: int, is_ssl: bool, timeout: float = 3.0) -> Tuple[bool, str]:
        """Helper issuing raw GET request over HTTP or HTTPS."""
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if is_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    s = ctx.wrap_socket(raw_sock, server_hostname=target_domain)
                except Exception:
                    s = ctx.wrap_socket(raw_sock)
            else:
                s = raw_sock

            s.connect((candidate_ip, port))

            request_str = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_domain}\r\n"
                f"User-Agent: Mozilla/5.0 (IP-Sentinel-Check)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(request_str.encode("utf-8"))
            response = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()

            lines = response.splitlines()
            if lines:
                status_line = lines[0]
                status_codes = ["200", "301", "302", "307", "308", "401", "403"]
                if any(code in status_line for code in status_codes):
                    return True, status_line
                return False, status_line
        except Exception as err:
            return False, str(err)
        return False, "No response"

    @staticmethod
    def validate_host_header(candidate_ip: str, target_domain: str, port: int = 80, timeout: float = 3.0) -> Tuple[bool, str]:
        """
        Validate candidate IP by issuing direct GET request with Host: <target_domain> header.
        Probes HTTP (80) and automatically falls back to HTTPS (443) with SSL wrapping.
        Returns (success, response_snippet).
        """
        # 1. Try plain HTTP (port 80)
        http_ok, http_res = OriginIPService._probe_http(candidate_ip, target_domain, port=80, is_ssl=False, timeout=timeout)
        if http_ok:
            return True, http_res

        # 2. Fallback to HTTPS (port 443) with SSL wrapping
        https_ok, https_res = OriginIPService._probe_http(candidate_ip, target_domain, port=443, is_ssl=True, timeout=timeout)
        if https_ok:
            return True, f"HTTPS (443): {https_res}"

        # If both fail, return descriptive error status
        if "timed out" in http_res.lower() and "timed out" in https_res.lower():
            return False, "Connection error: timed out (HTTP 80 & HTTPS 443)"
        return False, f"HTTP: {http_res} | HTTPS: {https_res}"

    @staticmethod
    def _parse_target_host_port(target: str, default_port: int = 443) -> Tuple[str, int]:
        """Extract clean hostname/IP and destination port from target input."""
        target = target.strip()
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or default_port
            return host, port

        # Handle IPv6 notation e.g. [::1]:443
        if target.startswith("[") and "]" in target:
            closing = target.find("]")
            host = target[1:closing]
            rest = target[closing + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    pass
            return host, default_port

        if ":" in target and target.count(":") == 1:
            parts = target.split(":")
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], default_port

        return target, default_port

    @staticmethod
    def _extract_rdn(rdn_tuples, key_name: str) -> str:
        """Extract a specific RDN attribute (e.g. 'commonName', 'organizationName') from subject/issuer tuples."""
        if not rdn_tuples:
            return ""
        try:
            for rdn in rdn_tuples:
                for item in rdn:
                    if isinstance(item, (tuple, list)) and len(item) == 2:
                        if item[0] == key_name:
                            return str(item[1])
        except Exception:
            pass
        return ""

    @staticmethod
    def _parse_cert_date(date_str: str) -> Optional[datetime.datetime]:
        """Parse certificate date string (e.g., 'Dec 21 19:20:01 2026 GMT') into UTC datetime."""
        if not date_str:
            return None
        cleaned = date_str.strip()
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%b %d %H:%M:%S %Y",
            "%b  %d %H:%M:%S %Y",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                continue

        tokens = cleaned.split()
        if len(tokens) >= 4:
            without_tz = " ".join(tokens[:-1])
            for fmt in ["%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y"]:
                try:
                    dt = datetime.datetime.strptime(without_tz, fmt)
                    return dt.replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    continue
        return None

    @staticmethod
    def inspect_certificate(target: str, port: int = 443, timeout: float = 5.0) -> SSLCertificateDetails:
        """
        Connect to target domain or raw candidate IP and extract complete SSL/TLS certificate metadata.
        Uses pure Python standard library (socket, ssl, hashlib, datetime, tempfile).
        """
        host, target_port = OriginIPService._parse_target_host_port(target, port)
        if not host:
            return SSLCertificateDetails(
                target=target,
                port=port,
                status="ERROR",
                error="Target host or IP cannot be empty",
            )

        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        raw_sock = None
        ssock = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection((host, target_port), timeout=timeout)
            server_hostname = None if is_ip else host

            try:
                ssock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname)
            except ssl.SSLError:
                if server_hostname:
                    # Retry without SNI in case server rejects unknown SNI hostname
                    raw_sock.close()
                    raw_sock = socket.create_connection((host, target_port), timeout=timeout)
                    ssock = ctx.wrap_socket(raw_sock, server_hostname=None)
                else:
                    raise

            der_bytes = ssock.getpeercert(binary_form=True)
            if not der_bytes:
                return SSLCertificateDetails(
                    target=host,
                    port=target_port,
                    status="ERROR",
                    error="No SSL certificate presented by remote host",
                )

            tls_version = ssock.version() or ""
            cipher_info = ssock.cipher()
            cipher_suite = cipher_info[0] if cipher_info else ""

            sha256_raw = hashlib.sha256(der_bytes).hexdigest().upper()
            sha256_fingerprint = ":".join(sha256_raw[i : i + 2] for i in range(0, len(sha256_raw), 2))

            pem_str = ssl.DER_cert_to_PEM_cert(der_bytes)
            cert_dict = {}
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
                tmp.write(pem_str)
                tmp_path = tmp.name

            try:
                if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                    cert_dict = ssl._ssl._test_decode_cert(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

            subject = cert_dict.get("subject", ())
            issuer = cert_dict.get("issuer", ())
            common_name = OriginIPService._extract_rdn(subject, "commonName")
            issuer_org = OriginIPService._extract_rdn(issuer, "organizationName")
            issuer_cn = OriginIPService._extract_rdn(issuer, "commonName")
            serial_number = str(cert_dict.get("serialNumber", ""))

            sans: List[str] = []
            for item in cert_dict.get("subjectAltName", ()):
                if isinstance(item, (tuple, list)) and len(item) == 2:
                    sans.append(str(item[1]))

            valid_from = str(cert_dict.get("notBefore", ""))
            valid_to = str(cert_dict.get("notAfter", ""))

            expiry_dt = OriginIPService._parse_cert_date(valid_to)
            days_remaining = 0
            if expiry_dt:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (expiry_dt - now_utc).days
                if days_remaining < 0:
                    status = "EXPIRED"
                elif days_remaining <= 30:
                    status = "EXPIRING_SOON"
                else:
                    status = "VALID"
            else:
                status = "UNKNOWN"

            return SSLCertificateDetails(
                target=host,
                port=target_port,
                common_name=common_name,
                sans=sans,
                issuer_org=issuer_org,
                issuer_cn=issuer_cn,
                valid_from=valid_from,
                valid_to=valid_to,
                days_remaining=days_remaining,
                status=status,
                serial_number=serial_number,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                sha256_fingerprint=sha256_fingerprint,
                error=None,
            )
        except Exception as e:
            logger.warning(f"SSL certificate inspection failed for {host}:{target_port}: {e}")
            return SSLCertificateDetails(
                target=host,
                port=target_port,
                status="ERROR",
                error=str(e),
            )
        finally:
            if ssock:
                try:
                    ssock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    @staticmethod
    def fetch_passive_dns_history(domain: str) -> List[HistoricalDNSRecord]:
        """
        Query passive DNS history archives (HackerTarget and AlienVault OTX)
        to identify historical IP addresses for a domain.
        """
        records: List[HistoricalDNSRecord] = []
        seen_pairs: Set[Tuple[str, str]] = set()  # (domain, ip)
        clean_domain = OriginIPService.extract_domain(domain)
        root_domain = ".".join(clean_domain.split(".")[-2:]) if len(clean_domain.split(".")) > 2 else clean_domain

        # 1. Query HackerTarget Hostsearch API
        try:
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
            req = urllib.request.Request(ht_url, headers={"User-Agent": "Mozilla/5.0 (IP-Sentinel-AI/5.0.0)"})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                    for line in lines:
                        if "," in line:
                            parts = line.strip().split(",")
                            if len(parts) >= 2:
                                h_name = parts[0].strip().lower()
                                h_ip = parts[1].strip()
                                try:
                                    ipaddress.ip_address(h_ip)
                                    pair = (h_name, h_ip)
                                    if pair not in seen_pairs:
                                        seen_pairs.add(pair)
                                        cdn_res = OriginIPService.check_cdn(h_ip)
                                        records.append(
                                            HistoricalDNSRecord(
                                                domain=h_name,
                                                ip=h_ip,
                                                source="HackerTarget",
                                                is_cdn=cdn_res.is_cdn,
                                                cdn_provider=cdn_res.provider,
                                            )
                                        )
                                except ValueError:
                                    continue
        except Exception as e:
            logger.debug(f"HackerTarget passive DNS lookup skipped or failed for {root_domain}: {e}")

        # 2. Query AlienVault OTX Passive DNS endpoint
        try:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root_domain}/passive_dns"
            headers = {"User-Agent": "IP-Sentinel-AI/5.0.0"}
            otx_key = os.environ.get("IPSENTINEL_KEY_ALIENVAULT") or os.environ.get("IPSENTINEL_KEY_ALIENVAULT_API_KEY")
            if otx_key:
                headers["X-OTX-API-KEY"] = otx_key

            req = urllib.request.Request(otx_url, headers=headers)
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    for entry in data.get("passive_dns", []):
                        rec_type = entry.get("record_type", "")
                        addr = entry.get("address", "").strip()
                        host_rec = entry.get("hostname", root_domain).strip().lower()
                        first_seen = entry.get("first", "")
                        last_seen = entry.get("last", "")

                        if rec_type == "A" and addr:
                            try:
                                ipaddress.ip_address(addr)
                                pair = (host_rec, addr)
                                if pair not in seen_pairs:
                                    seen_pairs.add(pair)
                                    cdn_res = OriginIPService.check_cdn(addr)
                                    records.append(
                                        HistoricalDNSRecord(
                                            domain=host_rec,
                                            ip=addr,
                                            first_seen=first_seen,
                                            last_seen=last_seen,
                                            source="AlienVault OTX",
                                            is_cdn=cdn_res.is_cdn,
                                            cdn_provider=cdn_res.provider,
                                        )
                                    )
                            except ValueError:
                                continue
        except Exception as e:
            logger.debug(f"AlienVault OTX passive DNS lookup skipped or failed for {root_domain}: {e}")

        # 3. Query Certspotter CT Log Archive (Resilient fallback when public APIs rate-limit)
        try:
            cs_url = f"https://api.certspotter.com/v1/issuances?domain={root_domain}&include_subdomains=true&expand=dns_names"
            cs_req = urllib.request.Request(cs_url, headers={"User-Agent": "Mozilla/5.0 (IP-Sentinel-AI/5.0.0)"})
            with urllib.request.urlopen(cs_req, timeout=5.0) as resp:
                if resp.status == 200:
                    cs_data = json.loads(resp.read().decode("utf-8"))
                    host_dates: Dict[str, Tuple[str, str]] = {}
                    for entry in cs_data[:35]:
                        nb = entry.get("not_before", "")[:10]
                        na = entry.get("not_after", "")[:10]
                        for dname in entry.get("dns_names", []):
                            clean_h = dname.strip().lower()
                            if clean_h and "*" not in clean_h and root_domain in clean_h:
                                if clean_h not in host_dates and len(host_dates) < 25:
                                    host_dates[clean_h] = (nb, na)

                    # Parallel DNS resolution across discovered unique hostnames
                    if host_dates:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                            fut_to_host = {
                                ex.submit(OriginIPService.resolve_dns, h): (h, dates)
                                for h, dates in host_dates.items()
                            }
                            for fut in concurrent.futures.as_completed(fut_to_host, timeout=5.0):
                                try:
                                    h, (nb, na) = fut_to_host[fut]
                                    ips = fut.result()
                                    for h_ip in ips:
                                        pair = (h, h_ip)
                                        if pair not in seen_pairs:
                                            seen_pairs.add(pair)
                                            cdn_res = OriginIPService.check_cdn(h_ip)
                                            records.append(
                                                HistoricalDNSRecord(
                                                    domain=h,
                                                    ip=h_ip,
                                                    first_seen=nb,
                                                    last_seen=na,
                                                    source="Certspotter CT Logs",
                                                    is_cdn=cdn_res.is_cdn,
                                                    cdn_provider=cdn_res.provider,
                                                )
                                            )
                                except Exception:
                                    pass
        except Exception as e:
            logger.debug(f"Certspotter passive DNS lookup skipped or failed for {root_domain}: {e}")

        return records

    @staticmethod
    def grab_port_banner(ip: str, port: int, timeout: float = 1.5) -> PortBanner:
        """
        Probe a single port on target IP and grab service banner/software version.
        Uses pure Python standard library socket and ssl.
        """
        svc_name, is_ssl = OriginIPService.PORT_SERVICE_MAP.get(port, (f"Port-{port}", False))

        raw_sock = None
        s = None
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if is_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw_sock.connect((ip, port))
                s = ctx.wrap_socket(raw_sock)
            else:
                raw_sock.connect((ip, port))
                s = raw_sock

            banner_text = ""

            if port in (80, 8080):
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: IP-Sentinel\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("utf-8"))
                resp = s.recv(2048).decode("utf-8", errors="ignore")
                headers = []
                for line in resp.splitlines():
                    low = line.lower()
                    if low.startswith("server:") or low.startswith("x-powered-by:"):
                        headers.append(line.strip())
                status_line = resp.splitlines()[0] if resp.splitlines() else "HTTP Open"
                banner_text = " | ".join(headers) if headers else status_line

            elif port in (443, 8443):
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: IP-Sentinel\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("utf-8"))
                resp = s.recv(2048).decode("utf-8", errors="ignore")
                headers = []
                for line in resp.splitlines():
                    low = line.lower()
                    if low.startswith("server:") or low.startswith("x-powered-by:"):
                        headers.append(line.strip())
                status_line = resp.splitlines()[0] if resp.splitlines() else "HTTPS Open (TLS)"
                banner_text = " | ".join(headers) if headers else status_line

            elif port == 21:
                raw = s.recv(1024).decode("utf-8", errors="ignore").strip()
                banner_text = raw or "FTP Service Ready"

            elif port == 22:
                raw = s.recv(1024).decode("utf-8", errors="ignore").strip()
                banner_text = raw or "OpenSSH Service"

            elif port == 3306:
                pkt = s.recv(1024)
                if len(pkt) > 5 and pkt[4] == 0x0A:
                    null_idx = pkt.find(b"\x00", 5)
                    if null_idx != -1:
                        ver = pkt[5:null_idx].decode("ascii", errors="ignore")
                        banner_text = f"MySQL Handshake (v{ver})"
                    else:
                        banner_text = "MySQL Database (Handshake ACK)"
                else:
                    banner_text = "MySQL Database (Open)"

            elif port == 3389:
                banner_text = "Microsoft Terminal Services (RDP)"

            else:
                try:
                    s.settimeout(0.5)
                    raw = s.recv(512).decode("utf-8", errors="ignore").strip()
                    banner_text = raw if raw else "TCP Service Active"
                except Exception:
                    banner_text = "TCP Service Active"

            return PortBanner(
                port=port,
                service_name=svc_name,
                state="OPEN",
                banner=banner_text or "Open",
                is_ssl=is_ssl,
            )

        except (socket.timeout, TimeoutError):
            return PortBanner(
                port=port,
                service_name=svc_name,
                state="FILTERED",
                banner="Connection timed out (Filtered / Firewall)",
                is_ssl=is_ssl,
            )
        except (ConnectionRefusedError, ConnectionResetError):
            return PortBanner(
                port=port,
                service_name=svc_name,
                state="CLOSED",
                banner="Connection refused",
                is_ssl=is_ssl,
            )
        except Exception as err:
            return PortBanner(
                port=port,
                service_name=svc_name,
                state="CLOSED",
                banner=str(err),
                is_ssl=is_ssl,
            )
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    @staticmethod
    def scan_ports_and_banners(ip: str, ports: Optional[List[int]] = None, timeout: float = 1.5) -> PortScanResult:
        """
        Scan a list of ports concurrently on target IP and grab software banners.
        """
        start = time.time()
        target_ports = ports or OriginIPService.DEFAULT_SCAN_PORTS
        results: List[PortBanner] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(target_ports), 8)) as executor:
            future_to_port = {
                executor.submit(OriginIPService.grab_port_banner, ip, port, timeout): port
                for port in target_ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    p = future_to_port[future]
                    svc, is_ssl = OriginIPService.PORT_SERVICE_MAP.get(p, (f"Port-{p}", False))
                    results.append(PortBanner(port=p, service_name=svc, state="ERROR", banner=str(e), is_ssl=is_ssl))

        results.sort(key=lambda x: x.port)
        elapsed = round(time.time() - start, 2)
        return PortScanResult(
            ip=ip,
            open_ports=results,
            scanned_ports=target_ports,
            execution_time_seconds=elapsed,
        )

    def run_discovery(self, target_url_or_domain: str, raw_email_headers: Optional[str] = None) -> OriginDiscoveryResult:
        """Execute full step-by-step Origin IP & CDN discovery workflow."""
        start_time = time.time()
        domain = self.extract_domain(target_url_or_domain)
        logger.info(f"Starting Origin IP discovery scan for domain: '{domain}'")

        resolved_ips = self.resolve_dns(domain)
        cdn_results: List[CDNCheckResult] = []
        is_behind_cdn = False

        for ip in resolved_ips:
            res = self.check_cdn(ip, domain=domain)
            cdn_results.append(res)
            if res.is_cdn:
                is_behind_cdn = True

        candidate_map: Dict[str, str] = {}  # ip -> source

        root_domain = ".".join(domain.split(".")[-2:]) if len(domain.split(".")) > 2 else domain

        # Phase 1: Subdomain scanning
        for sub in ORIGIN_SUBDOMAINS:
            sub_domain = f"{sub}.{root_domain}"
            sub_ips = self.resolve_dns(sub_domain)
            for ip in sub_ips:
                cdn_check = self.check_cdn(ip)
                if not cdn_check.is_cdn and ip not in resolved_ips:
                    candidate_map[ip] = f"Subdomain Scan ({sub_domain})"

        # Phase 2: crt.sh Certificate Transparency logs
        ct_subdomains = self.fetch_crt_sh_subdomains(root_domain)
        for sub in ct_subdomains[:20]:
            sub_ips = self.resolve_dns(sub)
            for ip in sub_ips:
                cdn_check = self.check_cdn(ip)
                if not cdn_check.is_cdn and ip not in resolved_ips:
                    candidate_map[ip] = f"CT Logs ({sub})"

        # Phase 3: Passive DNS Historical Records
        historical_records = self.fetch_passive_dns_history(root_domain)
        for h_rec in historical_records:
            if not h_rec.is_cdn and h_rec.ip not in resolved_ips:
                first_date = f" (first seen {h_rec.first_seen[:10]})" if h_rec.first_seen else ""
                candidate_map[h_rec.ip] = f"Passive DNS History ({h_rec.source}{first_date})"

        # Phase 4: Raw Email Headers
        email_analysis = None
        if raw_email_headers:
            email_analysis = self.parse_email_headers(raw_email_headers)
            for ip in email_analysis.candidate_origin_ips:
                candidate_map[ip] = "Email Header (Received From)"

        # Phase 5: Direct Host Header Validation Probing
        candidate_candidates: List[OriginCandidate] = []
        validated_candidates: List[OriginCandidate] = []

        for ip, source in candidate_map.items():
            valid, snippet = self.validate_host_header(ip, domain)
            cert_details = None
            if valid and "HTTPS" in snippet:
                try:
                    cert_details = self.inspect_certificate(ip, port=443, timeout=3.0)
                except Exception:
                    pass

            cand = OriginCandidate(
                ip=ip,
                discovery_source=source,
                validated=valid,
                http_status=snippet if valid else None,
                response_snippet=snippet,
                cert_details=cert_details,
            )
            candidate_candidates.append(cand)
            if valid:
                validated_candidates.append(cand)

        # Phase 6: Favicon Hash Calculation
        favicon_res = self.compute_favicon_hash(domain)

        elapsed = round(time.time() - start_time, 2)
        logger.info(
            f"Origin IP discovery finished for '{domain}' in {elapsed}s. "
            f"Behind CDN: {is_behind_cdn}, Validated Origins: {len(validated_candidates)}"
        )

        return OriginDiscoveryResult(
            target_url=target_url_or_domain,
            target_domain=domain,
            resolved_ips=resolved_ips,
            cdn_ips=cdn_results,
            candidate_origins=candidate_candidates,
            validated_origins=validated_candidates,
            favicon_result=favicon_res,
            email_analysis=email_analysis,
            historical_dns=historical_records,
            is_behind_cdn=is_behind_cdn,
            execution_time_seconds=elapsed,
        )
