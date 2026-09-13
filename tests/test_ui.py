"""Unit tests for PySide6 GUI MainWindow and view switching."""

from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.ui.main_window import MainWindow


def test_main_window_instantiation(qapp):
    svc = InvestigationService()
    win = MainWindow(service=svc)
    assert win.windowTitle().startswith("IP Sentinel AI")
    assert win.stacked_widget.count() == 6


def test_view_switching(qapp):
    svc = InvestigationService()
    win = MainWindow(service=svc)

    win.switch_view("query")
    assert win.stacked_widget.currentWidget() == win._views["query"]

    win.switch_view("waf")
    assert win.stacked_widget.currentWidget() == win._views["waf"]

    win.switch_view("reports")
    assert win.stacked_widget.currentWidget() == win._views["reports"]

    win.switch_view("logs")
    assert win.stacked_widget.currentWidget() == win._views["logs"]

    win.switch_view("settings")
    assert win.stacked_widget.currentWidget() == win._views["settings"]
