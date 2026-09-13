# CHANGELOG — IP Sentinel AI

All notable changes to **IP Sentinel AI** will be documented in this file.

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
