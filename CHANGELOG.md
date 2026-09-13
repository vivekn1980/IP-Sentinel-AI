# CHANGELOG — IP Sentinel AI

All notable changes to **IP Sentinel AI** will be documented in this file.

---

## [1.0.0-foundation] - 2026-09-13

### Added
- **Core Architecture Framework**:
  - `path_utils.py`: Centralized resource path resolution supporting PyInstaller `sys._MEIPASS` and dev mode.
  - `ip_utils.py`: Safe IPv4/IPv6 classification, private/loopback detection, CIDR validation using `ipaddress`.
  - `exceptions.py`: Custom exception hierarchy (`IPSentinelError`, `ConfigError`, `ProviderError`, `ReportError`, `NetworkError`, `ValidationError`) with Qt-aware global exception hook (`sys.excepthook`).
  - `config.py`: Thread-safe `ConfigManager` with JSON persistence under `%LOCALAPPDATA%\IPSentinelAI\config.json`, environment variable overrides, versioning, and `SecretStore` credentials abstraction.
  - `logger.py`: Thread-safe logging with rotating file handler (`ipsentinel.log`) and custom `QtSignalLogger` emitting PySide6 signals to UI log console with automated secret redaction.
  - `worker.py`: Asynchronous background task engine using `QRunnable` and `QThreadPool` with `WorkerSignals` to maintain 60 FPS UI responsiveness.

- **Data Models & Provider Abstraction**:
  - `threat_intel.py`: Normalized immutable DTOs (`IPIntelResult`, `ThreatScore`, `GeoIPData`, `ReputationData`, `DNSData`, `EvidenceItem`) with explicit status values (`AVAILABLE`, `UNAVAILABLE`, `ERROR`, `NOT_CONFIGURED`, `UNKNOWN`).
  - `base.py` (providers): Abstract Base Class `BaseIntelProvider`.
  - `mock_provider.py`: Deterministic `MockIntelProvider` producing realistic `CLEAN`, `SUSPICIOUS`, and `MALICIOUS` scenarios without Internet access.

- **Investigation Service Engine**:
  - `investigation_service.py`: Orchestrates IP validation, reverse DNS resolution (`dnspython`), provider queries, score aggregation, and fault-tolerant provider execution.

- **Forensic Report Generators**:
  - `html_generator.py`: Standalone HTML report generator using Jinja2 templates (`report_template.html`).
  - `pdf_generator.py`: Standalone PDF report generator using ReportLab Platypus elements.
  - Added mandatory `DEMO / MOCK DATA` warning banners when mock data is used.

- **PySide6 Desktop User Interface**:
  - Dark cybersecurity theme stylesheet (`dark_theme.qss`).
  - Sidebar navigation widget (`SidebarNavigation`) with active tab highlighting.
  - `DashboardView`: Overview metric cards, architecture status, and quick investigation buttons.
  - `QueryView`: IP lookup bar, asynchronous progress bar, risk score gauge, threat level badge, and structured evidence table.
  - `ReportsView`: HTML/PDF export configuration with folder picker and live generation progress.
  - `LogsView`: Real-time streaming audit console with log level filtering.
  - `SettingsView`: Provider credentials manager with masked password inputs.
  - `MainWindow`: Organizes sidebar, stacked widget views, header, and status bar.

- **CLI Options**:
  - Added `--version`, `--debug`, `--headless-test`, and `--self-test` diagnostic CLI flags in `main.py`.

- **Test Suite & Build System**:
  - 26 automated unit and integration tests in `tests/` covering all foundation subsystems (100% pass rate).
  - PyInstaller spec file (`pyinstaller.spec`) configured for single-file portable Windows EXE packaging (`dist/IP-Sentinel-AI.exe`).
  - Automated build (`build.py`) and clean (`clean_build.py`) scripts.
