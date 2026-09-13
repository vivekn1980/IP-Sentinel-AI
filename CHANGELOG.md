# CHANGELOG — IP Sentinel AI

All notable changes to **IP Sentinel AI** will be documented in this file.

---

## [4.0.0-phase4] - 2026-09-13

### Added
- **WAF Log Ingestion & Parser Abstraction**:
  - `waf_event.py`: Implemented normalized `WAFEvent` dataclass with fields for timestamp, IP, HTTP method, URI path, User-Agent, status code, rule ID, action, response size, host, and country.
  - `parsers/base.py`: Abstract `BaseWAFParser` with resilient row normalization.
  - `parsers/csv_parser.py` & `parsers/json_parser.py`: Implemented CSV, JSON array, and NDJSON/JSONL log parsers with flexible header and key aliases.
  - `parsers/vendor_stubs.py`: Architectural parser stubs for AWS WAF, Cloudflare, ModSecurity, and Akamai.
- **WAF Behavioral Analysis Service & Attack Classifier**:
  - `waf_analysis_service.py`: Computes traffic volume, average/peak req/sec & req/min, burst indicators, rate anomalies, UA diversity, dominant UA, missing UA ratios, URI probe hits (`CONFIG_DISCOVERY`, `ADMIN_ENUMERATION`, `CMS_SCAN`, `WEB_SCANNER`, `CREDENTIAL_ENDPOINT`), HTTP status code percentages (2xx, 3xx, 4xx, 5xx, 403, 404, 429), and temporal regularity scores.
  - `attack_classifier.py`: Evaluates behavioral indicators to compute evidence-backed attack classifications (`NORMAL_CLIENT`, `AUTOMATED_BOT`, `MALICIOUS_BOT`, `WEB_SCANNER`, `HTTP_FLOOD`, `CREDENTIAL_ATTACK`, `SUSPICIOUS_AUTOMATION`, `UNKNOWN`) with confidence ratings (0–100), supporting evidence, contradictory evidence, and limitations.
  - `waf_behavior.py`: Multi-dimensional `BehavioralFingerprint` model across 9 qualitative LOW/MEDIUM/HIGH dimensions.
- **UI Enhancements (`WAFAnalysisView`)**:
  - Added dedicated **WAF Analysis** sidebar navigation view featuring CSV/JSON upload buttons, executive metric summary cards, interactive IP breakdown table, and "⚡ Investigate Selected IP" transition.
- **Forensic Report Engine Updates**:
  - Updated Jinja2 HTML template and ReportLab PDF generator with WAF Behavioral Analysis, traffic stats, behavioral fingerprints, attack classifications, and mandatory behavioral disclaimers.
- **Test Suite & Deterministic Fixtures**:
  - Added 6 deterministic fixture log files (`clean_traffic.json`, `scanner_traffic.json`, `bot_traffic.json`, `flood_traffic.json`, `credential_attack.json`, `mixed_traffic.json`).
  - Added 18 new automated tests (`test_waf_parser.py`, `test_waf_analysis_service.py`, `test_attack_classifier.py`, `test_phase4_integration.py`, `test_phase4_reports.py`, `test_waf_ui.py`), bringing total automated test suite to **69 tests (100% pass rate)**.

---

## [3.0.0-phase3] - 2026-09-13

### Added
- **Live Threat Reputation Intelligence**:
  - `abuseipdb_provider.py`: Implemented AbuseIPDB API v2 `check` endpoint adapter retrieving abuse confidence score, total report count, distinct reporters, last reported timestamp, domain, usage type, and abuse categories with local TTL caching.
  - `virustotal_provider.py`: Implemented VirusTotal API v3 `ip_addresses` endpoint adapter retrieving malicious, suspicious, harmless, and undetected security engine detection counts with local TTL caching.
- **Evidence Correlation Engine (`evidence_aggregator.py`)**:
  - Normalizes telemetry from RDAP, GeoIP, DNS, WAF Context, AbuseIPDB, and VirusTotal.
  - Formats structured `EvidenceItem` objects with confidence levels, observations, and supporting data.
  - Calculates severity breakdown (CRITICAL, HIGH, MEDIUM, LOW, INFO) and automatically detects contradictory evidence.
- **Weighted Risk Assessment Engine (`risk_engine.py`)**:
  - Computes dynamic 0–100 overall risk score, qualitative threat level classification (`VERY_LOW`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and confidence rating based on multi-source evidence weights.
- **UI Enhancements (`QueryView` & `SettingsView`)**:
  - `QueryView`: Added AbuseIPDB and VirusTotal threat cards, Evidence Summary matrix, Evidence Table, Risk Assessment display, and Contradictory Evidence alert notice.
  - `SettingsView`: Added "Test Connection" functionality for validating AbuseIPDB and VirusTotal API keys with live feedback.
- **Forensic Report Engine Updates (`html_generator.py` & `pdf_generator.py`)**:
  - Updated Jinja2 HTML template (`report_template.html`) and ReportLab PDF generator to render threat feeds, evidence table, risk score, confidence ratings, and mandatory disclaimers.
- **Test Suite Expansion**:
  - Added 13 new unit and integration tests (`test_abuseipdb.py`, `test_virustotal.py`, `test_evidence_aggregator.py`, `test_risk_engine.py`, `test_phase3_investigation.py`, `test_phase3_reports.py`), bringing total automated test count to **51 tests (100% pass rate)**.

---

## [2.0.0-phase2] - 2026-09-13

### Added
- **Real Passive IP Intelligence Capabilities**:
  - `rdap_provider.py`: Implemented passive RDAP (Registration Data Access Protocol) bootstrap lookup retrieving network name, CIDR prefix, start/end IP, organization, country, abuse contact email, administrative contact, and registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
  - `geoip_provider.py`: Implemented passive GeoIP and ASN telemetry provider retrieving country code/name, region, city, timezone, ASN, AS organization, ISP, and approximate coordinates.
  - `dns_service.py`: Implemented safe non-intrusive DNS resolution querying PTR (reverse DNS), A, AAAA, MX, NS, TXT, and CNAME records with safe timeouts.
  - `cache.py`: Implemented thread-safe local file & memory TTL `CacheManager` storing JSON network lookup responses under `%LOCALAPPDATA%\IPSentinelAI\cache\`.

- **UI Updates (`QueryView`)**:
  - Added dedicated section cards for **IP INFORMATION**, **NETWORK & ASN**, **RDAP REGISTRATION**, **GEOLOCATION**, and **DNS TELEMETRY**.
  - Added explicit data status badges (`AVAILABLE`, `UNAVAILABLE`, `ERROR`, `UNKNOWN`) for every intelligence component.
  - Added step-by-step progress status updates during lookup (`Validating IP`, `Retrieving RDAP`, `Retrieving network information`, `Retrieving GeoIP`, `Performing reverse DNS`, `Performing DNS lookups`, `Building investigation result`, `Ready`).

- **Forensic Report Engine Updates**:
  - Updated Jinja2 HTML report template (`report_template.html`) and ReportLab PDF generator (`pdf_generator.py`) to include dedicated sections for IP Info, Network/ASN, RDAP, GeoIP, DNS, and Data Source Status Summary.
  - Added mandatory security disclaimer:  
    `"Network intelligence and geolocation are informational and may be approximate or incomplete. They should be correlated with WAF, application, CDN, firewall, and other security telemetry before making enforcement decisions."`

- **Test Suite Expansion**:
  - Added 12 new unit and integration tests in `tests/` (`test_cache.py`, `test_rdap.py`, `test_geoip.py`, `test_dns_service.py`, `test_phase2_investigation.py`, `test_phase2_reports.py`), bringing total automated test count to **38 tests (100% pass rate)**.
  - Updated `--self-test` CLI diagnostic in `main.py`.

---

## [1.0.0-foundation] - 2026-09-13

### Added
- Core architecture framework, `MockIntelProvider`, `InvestigationService`, PySide6 dark UI, HTML/PDF generators, `pytest` suite, and single-file portable Windows EXE build.
