# SECURITY.md — IP Sentinel AI Security Policy & Architecture

## 🛡️ Security Guidelines & Principles (Phase 2)

IP Sentinel AI is designed for WAF IP Threat Intelligence and incident investigation. Security is enforced through strict technical architecture controls.

---

## 1. Passive Network Operations Only

- **Zero Active Probing**: IP Sentinel AI **NEVER** performs port scanning, service enumeration, vulnerability scanning, active probing, or exploitation against target IP addresses.
- **Pure-Python Network Requests**: All network calls use standard Python library sockets (`dnspython`) or HTTPS over TLS (`requests`).

---

## 2. No Shell Command Execution (Command Injection Immunity)

- **Input Sanitization**: All user-supplied IP addresses are parsed and validated using Python's built-in `ipaddress` standard library (`ipaddress.ip_address`).
- **Zero OS Subprocesses**: IP Sentinel AI **NEVER** invokes shell commands (e.g. `ping`, `nslookup`, `traceroute`, `nmap`) using OS subprocesses or shell execution strings built from user input.

---

## 3. Mandatory Geolocation Disclaimer

- Network-level GeoIP coordinates are approximate and derived from Autonomous System (ASN) and ISP registration ranges.
- All application views and generated reports include the mandatory disclaimer:  
  `"GeoIP information represents approximate network geolocation and does not identify the physical location of an attacker."`

---

## 4. No Hardcoded Credentials & Secret Scrubbing

- **SecretStore Abstraction**: API keys (AbuseIPDB, VirusTotal) are managed via `ConfigManager` and stored securely in `%LOCALAPPDATA%\IPSentinelAI\credentials.json` or OS environment variables (`IPSENTINEL_KEY_ABUSEIPDB`, `IPSENTINEL_KEY_VIRUSTOTAL`).
- **Log Redaction**: `QtSignalLogger` and rotating file handlers enforce regex pattern matching (`SECRET_PATTERNS`) to scrub credentials before writing to disk or displaying in UI log console.

---

## 5. Threat Feed API & TLS Security

- **Strict TLS Verification**: All passive network requests to AbuseIPDB (`api.abuseipdb.com`), VirusTotal (`www.virustotal.com`), and RDAP bootstrap servers strictly require standard HTTPS TLS encryption.
- **Header Secret Protection**: API keys are passed strictly in HTTP request headers (`Key`, `x-apikey`), never in plaintext URL query parameters.
- **API Key UI Masking**: PySide6 settings UI masks API key fields with echo modes (`QLineEdit.Password`) and validates credentials on demand without logging raw key contents.

---

## 6. Report Injection Protection

- **Jinja2 Autoescaping**: `HTMLReportGenerator` uses Jinja2 template autoescaping (`autoescape=True`) to prevent Cross-Site Scripting (XSS) or HTML script injection when rendering RDAP strings or user notes into report files.
