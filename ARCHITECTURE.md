# ARCHITECTURE.md - IP Sentinel AI Technical Architecture

## 1. System Overview

**IP Sentinel AI** is a production-grade, standalone Windows desktop application designed for WAF IP Threat Intelligence gathering, incident investigation, and automated forensic report generation.

The core design principle is **Zero External Runtime Dependencies** on the target Windows machine. The application is compiled into a single portable `.exe` file via PyInstaller containing Python runtime, PySide6 GUI libraries, Jinja2, ReportLab, and network modules.

---

## 2. Architectural Principles & Patterns

The architecture strictly adheres to **SOLID** software engineering principles:

- **Single Responsibility Principle (SRP)**: Each package and module has a distinct responsibility. `ConfigManager` manages configuration, `BaseIntelProvider` handles API abstractions, `Worker` handles background threads, `ReportGenerator` creates artifacts.
- **Open/Closed Principle (OCP)**: Threat intelligence providers and report generators are extensible via abstract interfaces (`BaseIntelProvider`, `BaseReportGenerator`) without modifying core app execution logic.
- **Liskov Substitution Principle (LSP)**: All threat intelligence providers (mock, AbuseIPDB, VirusTotal, etc.) implement `BaseIntelProvider` and can be substituted transparently.
- **Interface Segregation Principle (ISP)**: Interfaces are lean and specialized (`WorkerSignals`, `BaseIntelProvider`, `BaseReportGenerator`).
- **Dependency Inversion Principle (DIP)**: Higher-level UI and orchestration modules depend on abstractions (`BaseIntelProvider`), not concrete network classes.

```
+-----------------------------------------------------------------------------------+
|                                  PySide6 UI Layer                                 |
|   MainWindow | Navigation | DashboardView | QueryView | ReportsView | SettingsView |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                              Core Application Engine                              |
|   SignalBus  |  Worker (QRunnable/QThread)  |  ConfigManager  |  ExceptionHook    |
+--------------------+--------------------+--------------------+--------------------+
                     |                    |                    |
                     v                    v                    v
+--------------------+---+   +------------+------------+   +---+--------------------+
| Threat Intel Providers |   |   Reporting Framework   |   | Logging & Audit System |
|   BaseIntelProvider    |   |   BaseReportGenerator   |   |   QtSignalLogger       |
|   MockIntelProvider    |   |   Jinja2 HTML & PDF     |   |   FileLogHandler       |
+------------------------+   +-------------------------+   +------------------------+
```

---

## 3. Project Structure

```
IP Sentinel AI/
├── ARCHITECTURE.md
├── requirements.txt
├── pytest.ini
├── pyinstaller.spec
├── src/
│   └── ip_sentinel/
│       ├── __init__.py
│       ├── main.py                    # Application Entry Point
│       ├── core/                      # Core infrastructure
│       │   ├── __init__.py
│       │   ├── config.py              # Configuration framework & key management
│       │   ├── logger.py              # Thread-safe logging framework & UI logger
│       │   ├── exceptions.py          # Unified exception hierarchy
│       │   ├── signals.py             # Global PySide6 SignalBus
│       │   └── worker.py              # QRunnable / QThreadPool background engine
│       ├── models/                    # Data transfer objects (DTOs)
│       │   ├── __init__.py
│       │   ├── ip_target.py           # Target IP validation DTO
│       │   ├── threat_intel.py        # Threat Intelligence Result DTOs
│       │   └── report_model.py        # Report generation DTOs
│       ├── providers/                 # Threat Intel Provider Abstraction
│       │   ├── __init__.py
│       │   ├── base.py                # Abstract Base BaseIntelProvider
│       │   └── mock_provider.py       # Mock Provider for UI/Integration tests
│       ├── reports/                   # PDF & HTML Report Abstraction
│       │   ├── __init__.py
│       │   ├── base.py                # Abstract Base BaseReportGenerator
│       │   ├── html_generator.py      # Jinja2 HTML Report Generator
│       │   └── pdf_generator.py       # ReportLab PDF Report Generator
│       ├── ui/                        # PySide6 GUI Components
│       │   ├── __init__.py
│       │   ├── main_window.py         # Main Application Window
│       │   ├── styles.py              # Dark Cybersecurity QSS Stylesheet
│       │   ├── navigation.py          # Sidebar Navigation Component
│       │   └── views/                 # Application Views
│       │       ├── __init__.py
│       │       ├── dashboard_view.py  # Overview & Stats View
│       │       ├── query_view.py      # IP Lookup & Investigation View
│       │       ├── reports_view.py    # Report Management & Export View
│       │       ├── logs_view.py       # Live Audit & System Logs View
│       │       └── settings_view.py   # API Keys & App Config View
│       └── utils/                     # Helper Utilities
│           ├── __init__.py
│           ├── ip_utils.py            # Sanitization, IPv4/v6 validation
│           └── path_utils.py          # PyInstaller sys._MEIPASS path resolver
├── resources/                         # Assets & Templates
│   ├── templates/
│   │   └── report_template.html       # Jinja2 HTML Report Template
│   └── styles/
│       └── dark_theme.qss             # Dark Theme Stylesheet
└── tests/                             # Comprehensive Unit & Integration Tests
    ├── __init__.py
    ├── conftest.py                    # Pytest fixtures & Qt app setup
    ├── test_config.py                 # Config framework tests
    ├── test_exceptions.py             # Custom exceptions & hooks tests
    ├── test_logger.py                 # Thread-safe logging tests
    ├── test_providers.py              # Provider interface & mock tests
    ├── test_reports.py                # HTML & PDF generator tests
    ├── test_worker.py                 # Multi-threading worker tests
    └── test_ui.py                     # PySide6 GUI component tests
```

---

## 4. Multi-Threading & Responsive UI Model

To prevent any UI freezing during DNS queries, API HTTP requests, or PDF report building, the UI thread delegates work to `QThreadPool` using `Worker(QRunnable)`.

### Thread Communication Pattern
1. **User triggers action** (e.g. click "Investigate IP").
2. **View instantiates `Worker(fn, *args)`** passing a target function.
3. **`WorkerSignals` emits signals**:
   - `started`: UI shows progress bar/spinner.
   - `result(data)`: UI receives `IPIntelResult` on the main thread and updates views.
   - `error(tuple)`: UI displays error dialog/banner if an exception occurs.
   - `finished`: UI resets button states.
4. **Main Thread stays 100% responsive** (60 FPS UI rendering preserved).

---

## 5. Security & Safety Principles

1. **No Hardcoded Credentials**: API keys are loaded dynamically from user configuration files or environment variables. No key is stored in source code.
2. **Command Injection Prevention**: No subprocesses execute shell commands built from user inputs. All IP lookups use standard library or pure-Python sockets (`dnspython`, `requests`).
3. **Strict Input Sanitization**: All incoming IP addresses are validated using Python's built-in `ipaddress` module (`ipaddress.ip_address`), discarding malformed inputs, loopback addresses, or private ranges before network execution.
4. **Global Exception Safeguard**: `sys.excepthook` is overridden with a custom Qt-aware handler that logs unexpected exceptions and alerts the user without crashing the process.

---

## 6. Configuration & Logging Architecture

- **`ConfigManager`**: A thread-safe Singleton/Manager handling JSON configuration persistence. Supports default settings fallbacks, auto-creation of default config directories, and atomic writes.
- **`QtSignalLogger`**: Custom `logging.Handler` that routes python log records through a PySide6 Signal to the UI log console view, enabling live audit log tracking.

---

## 7. Portable PyInstaller Packaging Model

When compiled with PyInstaller:
- Python dynamic assets (Jinja HTML templates, QSS stylesheets, ReportLab fonts) are packaged into `sys._MEIPASS`.
- `path_utils.get_resource_path()` dynamically resolves paths whether running in raw Python development mode or as a compiled frozen EXE.
