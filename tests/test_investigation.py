"""Unit tests for InvestigationService."""

import pytest
from ip_sentinel.core.exceptions import ValidationError
from ip_sentinel.models.threat_intel import DataStatus, ProviderResult, ThreatLevel
from ip_sentinel.providers.base import BaseIntelProvider
from ip_sentinel.services.investigation_service import InvestigationService


class FailingProvider(BaseIntelProvider):
    @property
    def provider_name(self) -> str:
        return "failing_provider"

    def is_configured(self) -> bool:
        return True

    def health_check(self) -> bool:
        return False

    def query_ip(self, target_ip: str) -> ProviderResult:
        raise RuntimeError("Simulated upstream API network failure")


def test_investigation_valid_ip(investigation_service):
    progress_updates = []

    def on_progress(pct, msg):
        progress_updates.append((pct, msg))

    res = investigation_service.investigate("185.220.101.5", progress_callback=on_progress)
    
    assert res.target_ip == "185.220.101.5"
    assert res.is_mock is True
    assert res.overall_threat_score.level == ThreatLevel.MALICIOUS
    assert len(progress_updates) > 0


def test_investigation_invalid_ip(investigation_service):
    with pytest.raises(ValidationError):
        investigation_service.investigate("invalid.ip.string")


def test_investigation_provider_failure_resilience(mock_provider):
    # Investigation should complete cleanly even if one provider throws an unhandled exception
    svc = InvestigationService(providers=[mock_provider, FailingProvider()])
    res = svc.investigate("198.51.100.45")

    assert res.target_ip == "198.51.100.45"
    assert "failing_provider" in res.provider_results
    assert res.provider_results["failing_provider"].status == DataStatus.ERROR
    assert "mock" in res.provider_results
    assert res.provider_results["mock"].status == DataStatus.AVAILABLE
