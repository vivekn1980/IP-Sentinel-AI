# SECURITY.md — IP Sentinel AI Security Policy & Architecture

## 🛡️ Security Guidelines & Principles

IP Sentinel AI is designed for cybersecurity operations and incident investigation. Security is enforced through strict technical architecture controls.

---

## 1. No Shell Command Execution (Command Injection Immunity)

- **Input Sanitization**: All user-supplied IP addresses are parsed and validated using Python's built-in `ipaddress` standard library (`ipaddress.ip_address`).
- **Zero OS Subprocesses**: IP Sentinel AI **NEVER** invokes shell commands (e.g. `ping`, `nslookup`, `traceroute`, `nmap`) using OS subprocesses or shell execution strings built from user input.
- **Pure-Python Network Resolution**: All DNS lookups use `dnspython` sockets; HTTP requests use `requests` over TLS.

---

## 2. No Hardcoded Credentials

- **SecretStore Abstraction**: API keys (AbuseIPDB, VirusTotal, Shodan, OTX) are strictly managed via `ConfigManager` and stored in `%LOCALAPPDATA%\IPSentinelAI\credentials.json` or OS environment variables (`IPSENTINEL_KEY_*`).
- **Zero In-Code Keys**: Source code contains no default or fallback API keys.

---

## 3. Secret Scrubbing in Logs & UI

- **Sensitive Data Filter**: `QtSignalLogger` and rotating file handlers enforce regex pattern matching (`SECRET_PATTERNS`) to scrub API keys, tokens, passwords, or bearer headers before writing to disk or displaying in the log console.

---

## 4. HTML & PDF Report Injection Protection

- **Jinja2 Autoescaping**: `HTMLReportGenerator` uses Jinja2 template autoescaping (`autoescape=True`) to prevent Cross-Site Scripting (XSS) or HTML script injection when rendering threat data or user notes into report files.

---

## 5. Non-Privileged Execution

- The application runs within normal Windows user context and does **NOT** require Administrator privileges or UAC elevation.
