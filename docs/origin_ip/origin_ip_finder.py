#!/usr/bin/env python3
"""
IP Sentinel AI - Origin IP & CDN IP Finder
------------------------------------------
Discovers CDN IPs and candidate Origin IPs for a given URL or domain.
"""

import sys
import os
import re
import socket
import ssl
import json
import ipaddress
import urllib.parse
import urllib.request

# Common public CIDRs for popular CDNs
CDN_CIDRS = {
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
        "151.101.0.0/16", "140.248.0.0/16", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16", "23.235.32.0/20", "45.33.32.0/20", "151.101.0.0/16"
    ],
    "Imperva / Incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
        "185.11.124.0/22", "192.230.64.0/18", "107.154.0.0/16", "45.55.0.0/16"
    ],
    "Sucuri": [
        "192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22"
    ],
    "BunnyCDN": [
        "185.246.208.0/22", "185.180.12.0/22", "169.150.192.0/18"
    ]
}

# Subdomain prefix candidates that often point directly to origin IP
ORIGIN_SUBDOMAINS = [
    "direct", "origin", "backend", "server", "main", "dev", "staging", "test",
    "mail", "cpanel", "webmail", "smtp", "pop", "ftp", "vpn", "m", "old",
    "admin", "api", "auth", "portal", "db", "mysql", "internal"
]

def extract_domain(input_url: str) -> str:
    """Extract host/domain from a URL string."""
    if not input_url.startswith(("http://", "https://")):
        input_url = "https://" + input_url
    parsed = urllib.parse.urlparse(input_url)
    domain = parsed.hostname or parsed.path.split("/")[0]
    return domain.lower().strip()

def check_ip_cdn(ip_str: str) -> str:
    """Check if an IP belongs to a known CDN range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for cdn_name, cidrs in CDN_CIDRS.items():
            for cidr in cidrs:
                if ip_obj in ipaddress.ip_network(cidr):
                    return cdn_name
    except ValueError:
        pass
    return None

def resolve_dns(domain: str):
    """Resolve A, AAAA, and CNAME records for a domain."""
    ips = set()
    try:
        info = socket.getaddrinfo(domain, None)
        for item in info:
            ip = item[4][0]
            ips.add(ip)
    except socket.gaierror:
        pass
    return list(ips)

def fetch_crt_sh_subdomains(domain: str):
    """Query CRT.sh Certificate Transparency logs for subdomains."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith("*"):
                        subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)

def test_direct_host_header(candidate_ip: str, target_domain: str, port=80, timeout=3):
    """
    Test if candidate IP responds to Host: <target_domain> header.
    Returns HTTP response status and snippet if valid.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((candidate_ip, port))
        
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_domain}\r\n"
            f"User-Agent: Mozilla/5.0 (IP-Sentinel-Check)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(request.encode('utf-8'))
        response = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()
        
        lines = response.splitlines()
        if lines:
            status_line = lines[0]
            return True, status_line
    except Exception as e:
        return False, str(e)
    return False, "No response"

def analyze_target(input_url: str):
    domain = extract_domain(input_url)
    print(f"==================================================")
    print(f"   IP SENTINEL AI - CDN & ORIGIN IP ANALYZER      ")
    print(f"==================================================")
    print(f"[*] Target Domain: {domain}\n")
    
    # 1. Resolve domain A/AAAA records
    print("[1] Querying DNS for target domain...")
    resolved_ips = resolve_dns(domain)
    
    cdn_ips = []
    direct_ips = []
    
    for ip in resolved_ips:
        cdn_name = check_ip_cdn(ip)
        if cdn_name:
            cdn_ips.append({"ip": ip, "provider": cdn_name})
            print(f"    [+] {ip} -> CDN Detected ({cdn_name})")
        else:
            direct_ips.append(ip)
            print(f"    [+] {ip} -> Non-CDN / Potential Direct IP")
            
    if not cdn_ips:
        print("    [!] Domain does not appear to be behind major CDN ranges.")
    
    # 2. Subdomain Origin Scanning
    print("\n[2] Scanning subdomains for potential Origin IP leak...")
    candidate_origins = set()
    
    root_domain = ".".join(domain.split(".")[-2:]) if len(domain.split(".")) > 2 else domain
    
    for sub in ORIGIN_SUBDOMAINS:
        candidate_domain = f"{sub}.{root_domain}"
        sub_ips = resolve_dns(candidate_domain)
        for ip in sub_ips:
            cdn = check_ip_cdn(ip)
            if not cdn:
                candidate_origins.add((ip, candidate_domain))
                print(f"    [!] Subdomain Leak: {candidate_domain} -> {ip}")

    # 3. Certificate Transparency Search
    print("\n[3] Searching Certificate Transparency (crt.sh) logs...")
    crt_subdomains = fetch_crt_sh_subdomains(root_domain)
    print(f"    [+] Found {len(crt_subdomains)} subdomains in CT logs.")
    
    # Check top candidate subdomains from CT logs
    for sub in crt_subdomains[:15]:
        sub_ips = resolve_dns(sub)
        for ip in sub_ips:
            cdn = check_ip_cdn(ip)
            if not cdn:
                candidate_origins.add((ip, sub))
                print(f"    [!] CT Subdomain: {sub} -> {ip}")

    # 4. Host Header Verification
    print("\n[4] Validating candidate Origin IPs via Host Header probing...")
    validated_origins = []
    
    for ip, source in candidate_origins:
        success, info = test_direct_host_header(ip, domain)
        if success:
            validated_origins.append({"ip": ip, "source": source, "response": info})
            print(f"    [✓] MATCH CONFIRMED! IP: {ip} (via {source}) -> HTTP Response: {info}")
        else:
            print(f"    [-] Tested {ip} (via {source}) -> {info}")

    # Summary
    print("\n==================================================")
    print("                ANALYSIS RESULTS                  ")
    print("==================================================")
    print(f"Target Domain: {domain}")
    print(f"CDN IPs Found: {[item['ip'] + ' (' + item['provider'] + ')' for item in cdn_ips]}")
    if validated_origins:
        print("\n[CONFIRMED ORIGIN IPs FOUND]:")
        for orig in validated_origins:
            print(f"  • IP: {orig['ip']} (Discovered via {orig['source']}) - Response: {orig['response']}")
    else:
        print("\n[ORIGIN IP]: Not directly leaked via basic subdomains/CT logs.")
        print("Recommended Next Steps: Use Censys SSL search, Shodan Favicon hash, or Email headers.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    analyze_target(target)
