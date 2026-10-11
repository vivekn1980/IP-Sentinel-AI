"""Unit tests for OriginFinderView PySide6 widget and MainWindow navigation integration."""

from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.ui.main_window import MainWindow
from ip_sentinel.ui.views.origin_finder_view import OriginFinderView


def test_origin_finder_view_instantiation(qapp):
    view = OriginFinderView()
    assert view.url_input is not None
    assert view.btn_scan is not None
    assert view.table_cdn.columnCount() == 3
    assert view.table_origins.columnCount() == 5


def test_main_window_origin_integration(qapp):
    svc = InvestigationService()
    win = MainWindow(service=svc)

    assert "origin" in win._views
    win.switch_view("origin")
    assert win.stacked_widget.currentWidget() == win._views["origin"]
    assert win.sidebar.active_view == "origin"


def test_signal_bus_worker_signals(qapp):
    from ip_sentinel.core.signals import SignalBus
    bus = SignalBus.instance()

    started_payload = []
    finished_calls = []

    bus.worker_started.connect(lambda msg: started_payload.append(msg))
    bus.worker_finished.connect(lambda: finished_calls.append(True))

    bus.worker_started.emit("Test Task")
    bus.worker_finished.emit()

    assert started_payload == ["Test Task"]
    assert len(finished_calls) == 1


def test_cert_inspector_ui_components(qapp):
    from ip_sentinel.models.origin_finder import SSLCertificateDetails
    view = OriginFinderView()

    assert view.tab_widget.count() == 4
    assert view.cert_target_input is not None
    assert view.cert_port_spin.value() == 443
    assert view.btn_inspect_cert is not None
    assert view.btn_copy_cert is not None

    # Simulate inspection completion
    sample_cert = SSLCertificateDetails(
        target="1.1.1.1",
        port=443,
        common_name="cloudflare-dns.com",
        sans=["cloudflare-dns.com", "1.1.1.1"],
        issuer_org="SSL Corp",
        issuer_cn="SSL.com Intermediate",
        valid_from="Dec 31 19:20:01 2025 GMT",
        valid_to="Dec 21 19:20:01 2026 GMT",
        days_remaining=71,
        status="VALID",
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        sha256_fingerprint="AA:BB:CC:DD",
    )

    view._on_cert_inspection_finished(sample_cert)

    assert "VALID CERTIFICATE" in view.cert_status_badge.text()
    assert "71 days" in view.lbl_cert_days_remaining.text()
    assert "cloudflare-dns.com" in view.lbl_cert_cn.text()
    assert "SSL Corp" in view.lbl_cert_issuer_org.text()
    assert "cloudflare-dns.com, 1.1.1.1" in view.txt_cert_sans.toPlainText()
    assert view.btn_copy_cert.isEnabled()


def test_inspect_cert_for_target_switch(qapp):
    view = OriginFinderView()
    assert view.tab_widget.currentIndex() == 0

    view.inspect_cert_for_target("192.0.2.1", 8443)
    assert view.tab_widget.currentIndex() == 3
    assert view.cert_target_input.text() == "192.0.2.1"
    assert view.cert_port_spin.value() == 8443


def test_pdns_ui_and_search_switch(qapp):
    from ip_sentinel.models.origin_finder import HistoricalDNSRecord
    view = OriginFinderView()

    assert view.pdns_domain_input is not None
    assert view.btn_pdns_search is not None
    assert view.table_pdns.columnCount() == 7

    view.search_pdns_for_target("target.com")
    assert view.tab_widget.currentIndex() == 1
    assert view.pdns_domain_input.text() == "target.com"

    sample_record = HistoricalDNSRecord(
        domain="target.com",
        ip="198.51.100.10",
        first_seen="2023-01-01",
        last_seen="2024-01-01",
        source="AlienVault OTX",
        is_cdn=False,
    )
    view._on_pdns_finished([sample_record])
    assert view.table_pdns.rowCount() == 1
    assert view.table_pdns.item(0, 1).text() == "198.51.100.10"
    assert view.btn_copy_pdns.isEnabled()


def test_port_scanner_ui_and_scan_switch(qapp):
    from ip_sentinel.models.origin_finder import PortBanner, PortScanResult
    view = OriginFinderView()

    assert view.port_ip_input is not None
    assert view.btn_port_scan is not None
    assert view.table_ports.columnCount() == 4

    view.scan_ports_for_target("192.0.2.5")
    assert view.tab_widget.currentIndex() == 2
    assert view.port_ip_input.text() == "192.0.2.5"

    sample_port = PortBanner(port=80, service_name="HTTP", state="OPEN", banner="nginx/1.18.0")
    sample_scan = PortScanResult(ip="192.0.2.5", open_ports=[sample_port], scanned_ports=[80], execution_time_seconds=0.2)
    view._on_port_scan_finished(sample_scan)
    assert view.table_ports.rowCount() == 1
    assert view.table_ports.item(0, 0).text() == "80"
    assert "nginx/1.18.0" in view.table_ports.item(0, 3).text()
    assert view.btn_copy_ports.isEnabled()
