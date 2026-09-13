"""Application Entry Point for IP Sentinel AI desktop GUI & CLI flags."""

import argparse
import logging
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ip_sentinel import __version__
from ip_sentinel.core.config import ConfigManager
from ip_sentinel.core.exceptions import setup_global_exception_handler
from ip_sentinel.core.logger import setup_logging
from ip_sentinel.core.path_utils import get_app_data_dir, get_resource_path
from ip_sentinel.models.report_model import ReportData, ReportMetadata
from ip_sentinel.providers.mock_provider import MockIntelProvider
from ip_sentinel.reports.html_generator import HTMLReportGenerator
from ip_sentinel.reports.pdf_generator import PDFReportGenerator
from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.ui.main_window import MainWindow
from ip_sentinel.ui.styles import apply_dark_theme

logger = logging.getLogger("ip_sentinel.main")


def run_self_test() -> int:
    """Execute diagnostic self-test suite checking all foundation subsystems.
    
    Returns:
        0 if all self-tests pass, 1 if any failure occurs.
    """
    print("=" * 60)
    print(f"RUNNING IP SENTINEL AI DIAGNOSTIC SELF-TEST (v{__version__})")
    print("=" * 60)
    
    passed = 0
    failed = 0

    def check(name: str, fn) -> bool:
        nonlocal passed, failed
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
            return True
        except Exception as err:
            print(f"  [FAIL] {name}: {err}")
            failed += 1
            return False

    # 1. Config Manager test
    def test_config():
        cfg = ConfigManager()
        settings = cfg.get_settings()
        assert settings.config_version == "1.0", f"Unexpected config version: {settings.config_version}"

    check("Configuration Framework", test_config)

    # 2. Resource Path Resolution test
    def test_resources():
        template_path = get_resource_path("templates/report_template.html")
        qss_path = get_resource_path("styles/dark_theme.qss")
        assert template_path.exists(), f"Missing template at {template_path}"
        assert qss_path.exists(), f"Missing QSS stylesheet at {qss_path}"

    check("Resource Paths Resolution", test_resources)

    # 3. Mock Provider test
    def test_mock_provider():
        prov = MockIntelProvider()
        assert prov.is_configured(), "Mock provider should be configured."
        res = prov.query_ip("185.220.101.5")
        assert res.threat_score and res.threat_score.score > 80, "Expected malicious score for test IP."

    check("Mock Intelligence Provider", test_mock_provider)

    # 4. Investigation Service test
    def test_investigation():
        svc = InvestigationService()
        result = svc.investigate("198.51.100.45")
        assert result.target_ip == "198.51.100.45", f"Mismatch target IP: {result.target_ip}"
        assert result.investigation_id.startswith("INV-"), "Missing valid investigation ID."

    check("Investigation Service Engine", test_investigation)

    # 5. HTML & PDF Generators test
    def test_reports():
        svc = InvestigationService()
        result = svc.investigate("1.1.1.1")
        data = ReportData(result=result, metadata=ReportMetadata())

        test_dir = get_app_data_dir() / "selftest_tmp"
        test_dir.mkdir(parents=True, exist_ok=True)

        html_file = test_dir / "selftest.html"
        pdf_file = test_dir / "selftest.pdf"

        HTMLReportGenerator().generate_report(data, html_file)
        PDFReportGenerator().generate_report(data, pdf_file)

        assert html_file.exists() and html_file.stat().st_size > 0, "HTML report generation failed."
        assert pdf_file.exists() and pdf_file.stat().st_size > 0, "PDF report generation failed."

        # Clean up temp test files
        try:
            html_file.unlink(missing_ok=True)
            pdf_file.unlink(missing_ok=True)
        except Exception:
            pass

    check("HTML & PDF Forensic Report Generators", test_reports)

    print("=" * 60)
    print(f"SELF-TEST RESULTS: {passed} PASSED, {failed} FAILED.")
    print("=" * 60)
    return 0 if failed == 0 else 1


def parse_args():
    parser = argparse.ArgumentParser(description="IP Sentinel AI - WAF Threat Intelligence Tool")
    parser.add_argument("--version", action="version", version=f"IP Sentinel AI v{__version__}")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG log level output")
    parser.add_argument("--headless-test", action="store_true", help="Initialize framework without GUI event loop")
    parser.add_argument("--self-test", action="store_true", help="Run diagnostic self-test suite and return exit code")
    return parser.parse_args()


def main():
    args = parse_args()

    # Log setup
    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(log_level)
    setup_global_exception_handler()

    if args.self_test:
        sys.exit(run_self_test())

    if args.headless_test:
        logger.info("Headless initialization check passed cleanly.")
        sys.exit(0)

    # Initialize PySide6 Application Loop
    app = QApplication(sys.argv)
    app.setApplicationName("IP Sentinel AI")
    app.setOrganizationName("IPSentinelAI")

    apply_dark_theme(app)

    service = InvestigationService()
    window = MainWindow(service=service)
    window.show()

    logger.info("IP Sentinel AI application GUI started.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
