# IP Sentinel AI — WAF IP Threat Intelligence & Investigation Tool

> **Phase 2 Release — Real Passive IP Intelligence**  
> Portable Standalone Windows Desktop Application for Incident Response & WAF Forensics.

---

## 🛡️ Executive Summary

**IP Sentinel AI** is a production-grade, standalone Windows desktop application built with PySide6 for WAF IP Threat Intelligence gathering, incident investigation, and automated forensic report generation (HTML & PDF).

### Key Features (Phase 2)
- **Real Passive IP Intelligence**: Collects live, factual network intelligence for public IPv4 and IPv6 addresses without active probing or port scanning.
  - **RDAP**: Network name, CIDR range, start/end IP, organization, country, abuse contact, administrative contact, registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
  - **ASN**: Autonomous System Number, AS organization, routing prefix, country.
  - **Geolocation**: Country, region, city, timezone, approximate coordinates with mandatory network-level disclaimer.
  - **DNS Telemetry**: Reverse PTR, A, AAAA, MX, NS, TXT, CNAME record resolution.
- **Zero Target Runtime Dependencies**: Distributed as a portable single-file Windows executable (`dist/IP-Sentinel-AI.exe`). The target Windows machine does **NOT** require Python, Node.js, Java, pip, Docker, or any database server.
- **Local TTL Caching**: Includes a thread-safe, file-backed JSON cache manager (`CacheManager`) to speed up repeat queries without requiring a database server.
- **Deterministic Mock Engine**: Preserves `MockIntelProvider` allowing offline verification of lookups, threat scoring, and PDF/HTML report creation.
- **Fault-Tolerant Resilience**: Provider and subsystem failures (e.g. GeoIP service timeout) are handled gracefully without aborting the overall investigation.
- **60 FPS Responsive GUI**: All network queries and ReportLab PDF rendering execute asynchronously in background thread pools (`QThreadPool` / `QRunnable`), keeping the PySide6 UI 100% fluid.
- **Strict Security**: Safe pure-Python HTTPS/DNS lookups, zero hardcoded credentials, zero shell command execution, and automated log secret redaction.

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

The project contains a comprehensive automated test suite in `tests/` (38 tests) covering configuration, cache manager, RDAP queries, GeoIP/ASN, DNS resolution, custom exceptions, IP utilities, thread-safe log scrubbing, mock providers, investigation service, report generators, worker thread signals, and PySide6 UI views.

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
