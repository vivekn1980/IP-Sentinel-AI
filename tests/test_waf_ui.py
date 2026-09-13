"""UI unit tests for PySide6 WAFAnalysisView component."""

import os
import pytest
from PySide6.QtCore import Qt

from ip_sentinel.ui.views.waf_analysis_view import WAFAnalysisView


def test_waf_analysis_view_instantiation(qtbot):
    view = WAFAnalysisView()
    qtbot.addWidget(view)

    assert view.btn_upload_csv is not None
    assert view.btn_upload_json is not None
    assert view.table is not None
    assert view.btn_investigate.isEnabled() is False


def test_waf_analysis_view_process_fixture(qtbot):
    view = WAFAnalysisView()
    qtbot.addWidget(view)

    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    if os.path.exists(fixture_path):
        res = view.waf_service.analyze_file(fixture_path)
        view._on_analysis_complete(res)

        assert view.table.rowCount() == 1
        assert view.table.item(0, 0).text() == "198.51.100.45"
        assert view.table.item(0, 5).text() == "WEB_SCANNER"
