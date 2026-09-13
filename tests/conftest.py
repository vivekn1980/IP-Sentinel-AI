"""Pytest fixtures for IP Sentinel AI test suite."""

import sys
import pytest
from pathlib import Path
from PySide6.QtWidgets import QApplication

# Ensure src is on python sys.path
src_dir = str(Path(__file__).resolve().parent.parent / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from ip_sentinel.core.config import ConfigManager
from ip_sentinel.models.report_model import ReportData, ReportMetadata
from ip_sentinel.providers.mock_provider import MockIntelProvider
from ip_sentinel.services.investigation_service import InvestigationService


@pytest.fixture(scope="session")
def qapp():
    """Session-scoped PySide6 QApplication fixture for offscreen GUI testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def tmp_config_file(tmp_path):
    """Fixture providing temporary config.json path."""
    return tmp_path / "test_config.json"


@pytest.fixture
def clean_config_mgr(tmp_config_file):
    """Fixture returning fresh ConfigManager bound to temporary config path."""
    ConfigManager._instance = None
    mgr = ConfigManager(config_path=tmp_config_file)
    return mgr


@pytest.fixture
def mock_provider():
    """Fixture providing MockIntelProvider instance."""
    return MockIntelProvider()


@pytest.fixture
def investigation_service(mock_provider):
    """Fixture providing InvestigationService with MockIntelProvider."""
    return InvestigationService(providers=[mock_provider])


@pytest.fixture
def mock_investigation_result(investigation_service):
    """Fixture returning completed mock investigation result."""
    return investigation_service.investigate("185.220.101.5")


@pytest.fixture
def sample_report_data(mock_investigation_result):
    """Fixture returning ReportData model."""
    return ReportData(
        result=mock_investigation_result,
        metadata=ReportMetadata(title="Test Threat Intelligence Report"),
    )
