# Origin IP & CDN IP Discovery Guide

This guide explains how to extract **CDN IP Addresses** and discover the real **Origin IP Address** behind a Content Delivery Network (CDN) such as Cloudflare, AWS CloudFront, Fastly, Akamai, Imperva, or Sucuri for any target URL or domain.

---

## 1. Overview: CDN IP vs. Origin IP

- **CDN IPs**: Anycast IP addresses belonging to the CDN provider. When users request `https://example.com`, DNS resolves to the CDN's edge proxy servers.
- **Origin IP**: The actual web server IP where the website host runs (e.g., AWS EC2, DigitalOcean droplet, Nginx/Apache server). The CDN reverse-proxies requests from edge nodes to this origin server.

---

## 2. Step-by-Step Methodology

### Phase A: Extracting CDN IP Addresses

1. **URL & Domain Extraction**:
   Extract hostname from URL (e.g., `https://www.example.com/path` -> `www.example.com`).

2. **DNS Record Lookup**:
   Query `A` (IPv4), `AAAA` (IPv6), and `CNAME` records:
   ```bash
   nslookup example.com
   dig A example.com
   dig CNAME example.com
   ```

3. **CDN Range Matching**:
   Compare the resolved IP addresses against known public CIDR ranges published by CDN vendors:
   - **Cloudflare**: `173.245.48.0/20`, `104.16.0.0/13`, `172.64.0.0/13`, etc.
   - **AWS CloudFront**: `13.32.0.0/15`, `52.84.0.0/15`, `54.192.0.0/16`, etc.
   - **Fastly**: `151.101.0.0/16`, `199.27.72.0/21`, etc.
   - **Akamai**: Resolves to `*.akamaiedge.net` CNAMEs.

---

### Phase B: Uncovering the Real Origin IP

When a domain is behind a CDN proxy, the real Origin IP can be discovered using these techniques:

#### Method 1: Subdomain Misconfigurations
Many subdomains bypass the CDN proxy (gray-clouded) and point directly to the origin server or same IP subnet:
- Common targets: `direct.example.com`, `origin.example.com`, `backend.example.com`, `mail.example.com`, `cpanel.example.com`, `vpn.example.com`, `dev.example.com`, `staging.example.com`, `ftp.example.com`.

#### Method 2: SSL/TLS Certificate Search (Censys & Certificate Transparency)
Searching global IPv4 scans for SSL certificates issued to `example.com`:
- **Censys Query**: `services.tls.certificates.leaf_data.names: "example.com" and not autonomous_system.name: "Cloudflare"`
- **crt.sh**: Find historical subdomains and test their resolved IPs.

#### Method 3: Favicon MMH3 Hash Matching (Shodan)
Every web app often has a unique `favicon.ico`. By hashing it with MurmurHash3, you can query Shodan:
```python
import mmh3, requests, base64
response = requests.get("https://example.com/favicon.ico")
favicon_hash = mmh3.hash(base64.encodebytes(response.content))
print(f"http.favicon.hash:{favicon_hash}")
```
Search Shodan: `http.favicon.hash:<hash>` to find servers hosting the identical favicon outside CDN ranges.

#### Method 4: Outgoing Email Headers / MX / SPF Records
If the site allows user registration, password resets, or contact forms:
1. Trigger an email from the website to your inbox.
2. Inspect the raw email headers (`Received: from ... [X.X.X.X]`).
3. The originating IP in the email header often leaks the real server IP.

#### Method 5: Direct Host Header Validation
Once candidate IPs `X.X.X.X` are found, send an HTTP GET request directly to the candidate IP with the target `Host` header:
```bash
curl -H "Host: example.com" http://X.X.X.X/
```
If the HTTP status code, title, and body match the target site, the Origin IP is verified!

---

## 3. Python Automation Tool

Run the included `origin_ip_finder.py` script:
```bash
python origin_ip_finder.py https://example.com
```

### Script Workflow:
1. Parses input URL to extract target hostname and root domain.
2. Resolves DNS records and identifies CDN provider IPs.
3. Queries CT logs and common subdomains for direct IP leaks.
4. Performs direct HTTP `Host: example.com` header probing against candidate IPs to confirm origin server matches.
