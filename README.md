# IP Sentinel AI — WAF IP Threat Intelligence & Investigation Tool

> **Foundation Architecture v1.0.0-foundation**  
> Portable Standalone Windows Desktop Application for Incident Response & WAF Forensics.

---

## 🛡️ Executive Summary

**IP Sentinel AI** is a production-grade, standalone Windows desktop application built with PySide6 for WAF IP Threat Intelligence gathering, incident investigation, and automated forensic report generation (HTML & PDF).

### Key Features
- **Zero Target Runtime Dependencies**: Distributed as a portable single-file Windows executable (`dist/IP-Sentinel-AI.exe`). The target Windows machine does **NOT** require Python, Node.js, Java, pip, Docker, or any database server.
- **Deterministic Mock Engine**: Includes a offline-capable `MockIntelProvider` allowing complete end-to-end testing of lookups, risk scoring, DNS resolution, and PDF/HTML report generation without API keys or Internet access.
- **60 FPS Responsive GUI**: All network queries and ReportLab PDF rendering execute asynchronously in background thread pools (`QThreadPool` / `QRunnable`), keeping the PySide6 UI 100% fluid.
- **Strict Security**: Zero hardcoded credentials, zero shell command execution (prevention of command injection via `ipaddress` validation), and automated log secret redaction.

---

## 📁 Architecture & Data Flow

```
UI (PySide6 QStackedWidget)
  ↓ (Asynchronous QThreadPool / Worker)
InvestigationService
  ↓
Providers (MockIntelProvider / Future API Adapters) & Local DNS
  ↓
Normalized Data Models (IPIntelResult, ThreatScore, EvidenceItem)
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

The project contains a comprehensive automated test suite in `tests/` covering configuration, custom exceptions, IP utilities, thread-safe log scrubbing, mock providers, investigation service, report generators, worker thread signals, and PySide6 UI views.

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

### Clean Workspace Script
```powershell
python clean_build.py
```

---

## 💻 Clean Machine Testing Protocol

To verify portable execution on a fresh Windows machine:

1. Copy `dist/IP-Sentinel-AI.exe` to a clean Windows machine without Python, Node.js, pip, Git, or database servers installed.
2. Double-click `IP-Sentinel-AI.exe`.
3. Perform an IP lookup (e.g. `185.220.101.5`).
4. Click **📄 Export Report** to generate HTML and PDF forensic reports.
5. Confirm report files are written cleanly to `Documents\IPSentinelReports\`.
6. Exit application.
