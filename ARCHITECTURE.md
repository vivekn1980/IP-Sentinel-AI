# ARCHITECTURE.md - IP Sentinel AI Technical Architecture

## 1. System Overview

**IP Sentinel AI** is a production-grade, standalone Windows desktop application designed for WAF IP Threat Intelligence gathering, passive network investigation, and automated forensic report generation (HTML & PDF).

The core design principle is **Zero External Runtime Dependencies** on the target Windows machine. The application is compiled into a single portable `.exe` file via PyInstaller containing Python runtime, PySide6 GUI libraries, Jinja2, ReportLab, dnspython, requests, and network modules.

---

## 2. Architectural Principles & Patterns

The architecture strictly adheres to **SOLID** software engineering principles:

- **Single Responsibility Principle (SRP)**:
  - `RDAPProvider`: Passive RDAP lookup & JSON parsing.
  - `GeoIPProvider`: Network-level geolocation & ASN retrieval.
  - `DNSService`: Standard DNS record resolution (PTR, A, AAAA, MX, NS, TXT, CNAME).
  - `AbuseIPDBProvider`: AbuseIPDB API v2 threat reputation adapter & category mapping.
  - `VirusTotalProvider`: VirusTotal API v3 threat reputation adapter & scanner metrics.
  - `EvidenceAggregator`: Multi-source telemetry normalization, deduplication & evidence item formatting.
  - `RiskEngine`: Dynamic weighted risk scoring (0–100), threat classification & confidence assessment.
  - `CacheManager`: File & memory TTL caching without a database server.
  - `InvestigationService`: High-level orchestration of network investigation workflows.
- **Open/Closed Principle (OCP)**: Threat intelligence providers and network services are extensible via abstract interfaces without modifying core execution logic.
- **Liskov Substitution Principle (LSP)**: Network intelligence providers implement clean interfaces and can be substituted transparently.
- **Interface Segregation Principle (ISP)**: Interfaces are lean and specialized (`WorkerSignals`, `BaseIntelProvider`, `BaseReportGenerator`).
- **Dependency Inversion Principle (DIP)**: Higher-level UI and orchestration modules depend on abstractions, not concrete network implementations.

```
+-----------------------------------------------------------------------------------+
|                                  PySide6 UI Layer                                 |
|   MainWindow | Navigation | DashboardView | QueryView | ReportsView | SettingsView |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v (Asynchronous QThreadPool / Worker)
+-----------------------------------------------------------------------------------+
|                              InvestigationService                                 |
|   Orchestrator | CacheManager (TTL) | SignalBus | ExceptionHook | ConfigManager   |
+----+--------------+---------------+-----------------+------------------+----------+
     |              |               |                 |                  |
     v              v               v                 v                  v
+----------+  +-----------+  +-------------+  +---------------+  +---------------+
|   RDAP   |  |   GeoIP   |  | DNS Service |  |  AbuseIPDB    |  |  VirusTotal   |
| Bootstrap|  | ASN/Geo   |  | PTR/A/MX... |  | API v2 Check  |  | API v3 IP     |
+----+-----+  +-----+-----+  +------+------+  +-------+-------+  +-------+-------+
     |              |               |                 |                  |
     +--------------+---------------+-----------------+------------------+
                                    |
                                    v
                        +-----------------------+
                        |   EvidenceAggregator  |
                        +-----------+-----------+
                                    |
                                    v
                        +-----------------------+
                        |      RiskEngine       |
                        | (Risk Score 0-100)    |
                        +-----------------------+
```

---

## 3. Project Structure

```
IP Sentinel AI/
├── ARCHITECTURE.md
├── SECURITY.md
├── README.md
├── CHANGELOG.md
├── requirements.txt
├── pytest.ini
├── pyinstaller.spec
├── build.py
├── clean_build.py
├── src/
│   └── ip_sentinel/
│       ├── __init__.py
│       ├── main.py                    # Application Entry Point & CLI flags
│       ├── core/                      # Core infrastructure
│       │   ├── __init__.py
│       │   ├── cache.py               # Local TTL JSON Cache Manager
│       │   ├── config.py              # Configuration framework & SecretStore
│       │   ├── logger.py              # Thread-safe logging framework & UI logger
│       │   ├── exceptions.py          # Unified exception hierarchy
│       │   ├── signals.py             # Global PySide6 SignalBus
│       │   ├── worker.py              # QRunnable / QThreadPool background engine
│       │   ├── ip_utils.py            # Sanitization, IPv4/v6 validation
│       │   └── path_utils.py          # PyInstaller sys._MEIPASS path resolver
│       ├── models/                    # Data transfer objects (DTOs)
│       │   ├── __init__.py
│       │   ├── threat_intel.py        # Threat Intel, RDAP, ASN, GeoIP, DNS DTOs
│       │   └── report_model.py        # Report generation DTOs
│       ├── providers/                 # Intelligence Providers
│       │   ├── __init__.py
│       │   ├── base.py                # Abstract Base BaseIntelProvider
│       │   ├── mock_provider.py       # Deterministic Mock Provider
│       │   ├── rdap_provider.py       # Passive RDAP Provider
│       │   └── geoip_provider.py      # Passive GeoIP & ASN Provider
│       ├── services/                  # Business Logic Services
│       │   ├── __init__.py
│       │   ├── dns_service.py         # Standard DNS Resolution Service
│       │   └── investigation_service.py # Master Investigation Orchestrator
│       ├── reports/                   # PDF & HTML Report Engine
│       │   ├── __init__.py
│       │   ├── base.py                # Abstract Base BaseReportGenerator
│       │   ├── html_generator.py      # Jinja2 HTML Report Generator
│       │   └── pdf_generator.py       # ReportLab PDF Report Generator
│       └── ui/                        # PySide6 GUI Components
│           ├── __init__.py
│           ├── main_window.py         # Main Application Window
│           ├── styles.py              # Dark Cybersecurity QSS Stylesheet
│           ├── navigation.py          # Sidebar Navigation Component
│           └── views/                 # Application Views
│               ├── dashboard_view.py  # Overview & Stats View
│               ├── query_view.py      # Real IP & Network Investigation View
│               ├── reports_view.py    # Report Management & Export View
│               ├── logs_view.py       # Live Audit & System Logs View
│               └── settings_view.py   # API Keys & App Config View
├── resources/                         # Assets & Templates
│   ├── templates/
│   │   └── report_template.html       # Jinja2 HTML Report Template
│   └── styles/
│       └── dark_theme.qss             # Dark Theme Stylesheet
└── tests/                             # Comprehensive Unit & Integration Tests (38 tests)
```

---

## 4. Multi-Threading & Responsive UI Model

To prevent any UI freezing during DNS queries, HTTPS network calls, or PDF report building, the UI thread delegates work to `QThreadPool` using `Worker(QRunnable)`.

---

## 5. Security & Safety Principles (Phase 2)

1. **Passive Operations Only**: Zero port scanning, zero active probing, zero exploit payloads. All network calls are 100% passive HTTPS/DNS queries.
2. **Mandatory Geolocation Disclaimer**: Every UI view and report contains the explicit disclaimer:  
   `"GeoIP information represents approximate network geolocation and does not identify the physical location of an attacker."`
3. **Fault-Tolerant Resilience**: If a subsystem (e.g. GeoIP endpoint) fails or times out, its status is marked `ERROR` / `UNAVAILABLE`, and the rest of the investigation completes cleanly.
