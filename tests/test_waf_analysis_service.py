"""Unit tests for WAFAnalysisService metrics and telemetry calculations."""

import os
from ip_sentinel.services.waf_analysis_service import WAFAnalysisService


def test_waf_analysis_service_scanner_fixture():
    service = WAFAnalysisService()
    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    assert os.path.exists(fixture_path)

    result = service.analyze_file(fixture_path)
    assert result.total_events >= 5
    assert result.unique_ips_count == 1
    assert "198.51.100.45" in result.ip_analyses

    an = result.ip_analyses["198.51.100.45"]
    assert an.config_file_hits > 0
    assert an.admin_endpoint_hits > 0
    assert an.pct_404 >= 40.0
    assert an.primary_classification.value == "WEB_SCANNER"
    assert an.risk_score >= 70


def test_waf_analysis_service_clean_fixture():
    service = WAFAnalysisService()
    fixture_path = os.path.join("resources", "fixtures", "clean_traffic.json")
    assert os.path.exists(fixture_path)

    result = service.analyze_file(fixture_path)
    assert result.total_events >= 4
    an = result.ip_analyses["203.0.113.15"]
    assert an.pct_2xx >= 80.0
    assert an.config_file_hits == 0
    assert an.primary_classification.value == "NORMAL_CLIENT"
    assert an.risk_score < 40


def test_waf_analysis_service_flood_fixture():
    service = WAFAnalysisService()
    fixture_path = os.path.join("resources", "fixtures", "flood_traffic.json")
    assert os.path.exists(fixture_path)

    result = service.analyze_file(fixture_path)
    an = result.ip_analyses["198.51.100.99"]
    assert an.is_bursty or an.peak_req_per_sec >= 3.0
    assert an.primary_classification.value in ("HTTP_FLOOD", "SUSPICIOUS_AUTOMATION", "AUTOMATED_BOT", "MALICIOUS_BOT")
