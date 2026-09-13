# IP Sentinel AI — WAF IP Threat Intelligence & Investigation Tool

> **Phase 3 Release — Live Threat Reputation & Evidence Correlation**  
> Portable Standalone Windows Desktop Application for Incident Response & WAF Forensics.

---

## 🛡️ Executive Summary

**IP Sentinel AI** is a production-grade, standalone Windows desktop application built with PySide6 for WAF IP Threat Intelligence gathering, incident investigation, risk assessment, and automated forensic report generation (HTML & PDF).

### Key Features (Phase 3)
- **Live Threat Reputation**:
  - **AbuseIPDB Adapter**: Queries AbuseIPDB API v2 `check` endpoint for abuse confidence score, total reports, distinct reporters, last reported timestamp, domain, usage type, and abuse categories.
  - **VirusTotal Adapter**: Queries VirusTotal API v3 `ip_addresses` endpoint for malicious, suspicious, harmless, and undetected engine metrics.
- **Evidence Correlation Engine (`EvidenceAggregator`)**:
  - Automatically normalizes telemetry across RDAP, GeoIP, DNS, WAF Context, AbuseIPDB, and VirusTotal.
  - Generates structured, deduplicated evidence items with observation descriptions, confidence levels, and supporting metadata.
  - Calculates severity counts and flags contradictory evidence (e.g. AbuseIPDB HIGH vs VirusTotal CLEAN, or Cloud/Datacenter IP with zero reports).
- **Weighted Risk Assessment Engine (`RiskEngine`)**:
  - Computes an objective risk score (0–100), threat level classification (`VERY_LOW`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and overall confidence score based on multi-source evidence weights.
- **WAF Attack Context Correlation**:
  - Supports correlating target IPs against WAF telemetry (Rule ID, Rule Description, URI Path, User-Agent, Attack Vector).
- **Real Passive Network Intelligence (Phase 2 Baseline)**:
  - **RDAP**: Network name, CIDR range, start/end IP, organization, country, abuse contact, administrative contact, registry.
  - **ASN & GeoIP**: Autonomous System Number, AS organization, routing prefix, country, region, city, timezone, approximate coordinates.
  - **DNS Telemetry**: Reverse PTR, A, AAAA, MX, NS, TXT, CNAME record resolution.
- **Zero Target Runtime Dependencies**: Distributed as a portable single-file Windows executable (`dist/IP-Sentinel-AI.exe`). The target Windows machine does **NOT** require Python, Node.js, Java, pip, Docker, or any database server.
- **Secure Secret Storage**: API keys are securely loaded from `%LOCALAPPDATA%\IPSentinelAI\credentials.json` or environment variables without hardcoded secrets. Includes UI connection testing for AbuseIPDB and VirusTotal.
- **Local TTL Caching**: Thread-safe, file-backed JSON cache manager (`CacheManager`) to speed up repeat queries.
- **Deterministic Mock Engine**: Preserves `MockIntelProvider` for offline testing and air-gapped forensic report generation.
- **Fault-Tolerant Resilience**: Provider failures (e.g., HTTP 401, 429, timeout) are gracefully handled as provider status indicators (`NOT_CONFIGURED`, `RATE_LIMITED`, `ERROR`) without breaking the investigation pipeline.
- **60 FPS Responsive GUI**: Asynchronous multi-threading via `QThreadPool` / `QRunnable` keeps PySide6 UI smooth during live network lookups and PDF generation.
- **Forensic HTML & PDF Reports**: Includes Jinja2 HTML templates and ReportLab Platypus PDF reports featuring Phase 3 Threat Reputation Feeds, Evidence Summary Matrix, Evidence Table, Risk Score & Threat Level, and Mandatory Disclaimers.

---

## 📁 Architecture & Data Flow

```
UI (PySide6 QStackedWidget)
  ↓ (Asynchronous QThreadPool / Worker)
InvestigationService
  ├─► RDAPProvider (Passive HTTPS bootstrap lookup)
  ├─► GeoIPProvider (Passive GeoIP & ASN query)
  ├─► DNSService (dnspython PTR, A, AAAA, MX, NS, TXT, CNAME)
  ├─► CacheManager (File & memory TTL cache)
  └─► BaseIntelProvider (MockIntelProvider / Threat Intel Adapters)
  ↓
Normalized Data Models (IPIntelResult, RDAPData, ASNData, GeoIPData, DNSData)
  ↓
Report Generators (Jinja2 HTML & ReportLab Platypus PDF)
```

For complete technical documentation, see [`ARCHITECTURE.md`](file:///d:/PROJECTS/IP%20Sentinel%20AI/ARCHITECTURE.md) and [`SECURITY.md`](file:///d:/PROJECTS/IP%20Sentinel%20AI/SECURITY.md).

---

## ⚙️ Development Setup & Running from Source

### Prerequisites
- Python 3.13 (x64) on Windows
- Git

### 1. Virtual Environment & Dependencies Setup
```powershell
# Create Python 3.13 virtual environment
py -3.13 -m venv .venv

# Activate environment
.\.venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt
```

### 2. Running Application from Source
```powershell
# Set PYTHONPATH to src directory
$env:PYTHONPATH="src"

# Launch PySide6 Desktop GUI
python -m ip_sentinel.main
```

### 3. CLI Command Options
```powershell
# Check Version
python -m ip_sentinel.main --version

# Enable Debug Logging
python -m ip_sentinel.main --debug

# Headless Initialization Check
python -m ip_sentinel.main --headless-test

# Diagnostic Self-Test (Returns Exit Code 0 on Success)
python -m ip_sentinel.main --self-test
```

---

## 🧪 Automated Testing

The project contains a comprehensive automated test suite in `tests/` (**51 tests**) covering configuration, cache manager, RDAP queries, GeoIP/ASN, DNS resolution, AbuseIPDB provider, VirusTotal provider, evidence aggregator, risk engine, custom exceptions, IP utilities, thread-safe log scrubbing, mock providers, investigation service, report generators, worker thread signals, and PySide6 UI views.

```powershell
# Run full pytest suite
pytest
```

---

## 📦 Packaging Portable Windows Executable (EXE)

To compile the standalone portable binary (`dist/IP-Sentinel-AI.exe`):

```powershell
# Run automated build script (cleans workspace, runs pytest, builds EXE)
python build.py
```

The compiled binary will be placed at:
```
dist/IP-Sentinel-AI.exe
```

---

## 💻 Clean Machine Testing Protocol

To verify portable execution on a fresh Windows machine:

1. Copy `dist/IP-Sentinel-AI.exe` to a clean Windows machine without Python, Node.js, pip, Git, or database servers installed.
2. Double-click `IP-Sentinel-AI.exe`.
3. Enter a public IP address (e.g. `1.1.1.1` or `8.8.8.8`).
4. Click **⚡ Analyze IP** to view RDAP, ASN, GeoIP, and DNS telemetry.
5. Click **📄 Export Report** to generate HTML and PDF forensic reports.
6. Confirm report files are written cleanly to `Documents\IPSentinelReports\`.
7. Exit application.
