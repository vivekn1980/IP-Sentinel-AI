# IP Sentinel AI — WAF IP Threat Intelligence & Investigation Tool

> **Phase 4 Release — WAF Behavioral & Attack Analysis Engine**  
> Portable Standalone Windows Desktop Application for WAF Log Ingestion, Incident Response & Forensics.

---

## 🛡️ Executive Summary

**IP Sentinel AI** is a production-grade, standalone Windows desktop application built with PySide6 for WAF IP Threat Intelligence gathering, passive WAF log behavioral analysis, incident investigation, risk assessment, and automated forensic report generation (HTML & PDF).

### Key Features (Phase 4)
- **WAF Behavioral & Attack Analysis Engine**:
  - **Multi-Format WAF Log Ingestion**: Ingests and parses WAF log files via flexible CSV and JSON/NDJSON parsers (`CSVWAFParser`, `JSONWAFParser`) with extensible architecture for AWS WAF, Cloudflare, ModSecurity, and Akamai.
  - **Traffic Volume & Rate Telemetry**: Calculates total requests, observation time window, average/peak requests per second & minute, rate distribution, temporal burstiness, and request rate anomalies.
  - **User-Agent Analysis**: Computes unique UA count, dominant UA, dominant UA ratio, missing UA percentage, and UA diversity.
  - **URI & Sensitive Endpoint Targeting**: Analyzes unique URI count, repeated URI ratio, 404 URI ratio, and flags probes against sensitive path categories (`CONFIG_DISCOVERY` e.g. `/.env`, `/.git`, `ADMIN_ENUMERATION` e.g. `/admin`, `/phpmyadmin`, `CMS_SCAN` e.g. `/wp-login.php`, `WEB_SCANNER` e.g. `/etc/passwd`, `/shell`, `CREDENTIAL_ENDPOINT` e.g. `/login`, `/oauth/token`).
  - **HTTP Status Code Breakdown**: Tracks 2xx, 3xx, 4xx, 5xx, 403, 404, and 429 response percentages.
  - **Request Pattern & Temporal Regularity**: Computes temporal interval regularity scores (0–100), request repetition, and HTTP method GET/POST ratios.
  - **Evidence-Backed Attack Classification (`AttackClassifier`)**: Classifies traffic into `NORMAL_CLIENT`, `AUTOMATED_BOT`, `MALICIOUS_BOT`, `WEB_SCANNER`, `HTTP_FLOOD`, `CREDENTIAL_ATTACK`, `SUSPICIOUS_AUTOMATION`, or `UNKNOWN` with confidence ratings (0–100), supporting evidence, contradictory evidence, and limitations.
  - **Multi-Dimensional Behavioral Fingerprint**: Generates qualitative `LOW`/`MEDIUM`/`HIGH` ratings across 9 behavioral dimensions.
- **WAF Analysis UI View (`WAFAnalysisView`)**:
  - Dedicated GUI view featuring CSV/JSON log file upload buttons, executive metric summary cards (Total Events, Unique IPs, Time Range, High Risk IPs), interactive sortable IP telemetry table, and one-click **"⚡ Investigate Selected IP"** action.
- **Live Threat Reputation & Network Intelligence (Phase 2/3 Baseline)**:
  - AbuseIPDB API v2, VirusTotal API v3, RDAP bootstrap queries, GeoIP/ASN telemetry, and DNS record resolution (PTR, A, AAAA, MX, NS, TXT, CNAME).
- **Multi-Source Evidence Correlation & Risk Engine**:
  - Normalizes findings across all subsystems into structured `EvidenceItem` records, calculates severity summaries, and blends WAF behavioral scores with reputation feeds while detecting contradictory evidence.
- **Forensic HTML & PDF Reports**:
  - Includes dedicated WAF Behavioral Analysis sections, traffic statistics, behavioral fingerprints, attack classification, evidence matrix, and mandatory behavioral disclaimers.
- **Zero Target Runtime Dependencies**:
  - Portable single-file Windows executable (`dist/IP-Sentinel-AI.exe`). No Python, Node.js, Java, Docker, or database server required on target Windows machines.

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

The project contains a comprehensive automated test suite in `tests/` (**69 tests**) covering configuration, cache manager, RDAP queries, GeoIP/ASN, DNS resolution, AbuseIPDB provider, VirusTotal provider, evidence aggregator, risk engine, CSV WAF parser, JSON WAF parser, WAF analysis service, attack classifier, custom exceptions, IP utilities, thread-safe log scrubbing, mock providers, investigation service, report generators, worker thread signals, and PySide6 UI views.

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
