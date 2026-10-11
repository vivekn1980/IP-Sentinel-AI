"""Main Application Window organizing navigation sidebar, stacked views, and status bar."""

import logging
from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ip_sentinel.core.path_utils import is_frozen
from ip_sentinel.core.signals import SignalBus
from ip_sentinel.services.investigation_service import InvestigationService
from ip_sentinel.ui.navigation import SidebarNavigation
from ip_sentinel.ui.views.dashboard_view import DashboardView
from ip_sentinel.ui.views.logs_view import LogsView
from ip_sentinel.ui.views.origin_finder_view import OriginFinderView
from ip_sentinel.ui.views.query_view import QueryView
from ip_sentinel.ui.views.reports_view import ReportsView
from ip_sentinel.ui.views.settings_view import SettingsView
from ip_sentinel.ui.views.waf_analysis_view import WAFAnalysisView

logger = logging.getLogger("ip_sentinel.ui.main_window")


class MainWindow(QMainWindow):
    """Main window shell for IP Sentinel AI PySide6 desktop GUI."""

    def __init__(self, service: InvestigationService):
        super().__init__()
        self.service = service
        self.setWindowTitle("IP Sentinel AI - WAF Threat Intelligence & Investigation Tool")
        self.resize(1180, 760)
        self.setMinimumSize(960, 600)

        self._views = {}
        self._setup_ui()

        # Connect to SignalBus navigation & worker requests
        bus = SignalBus.instance()
        bus.navigation_requested.connect(self.switch_view)
        bus.worker_started.connect(lambda name: self.status_bar.showMessage(f"Running background task: {name}..."))
        bus.worker_finished.connect(lambda: self.status_bar.showMessage("Task completed successfully."))

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Left Sidebar Navigation
        self.sidebar = SidebarNavigation()
        self.sidebar.view_changed.connect(self.switch_view)
        main_layout.addWidget(self.sidebar)

        # 2. Right Central Area (Header + Stacked Widget)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Top Bar Header
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: #171E28; border-bottom: 1px solid #2A3649; min-height: 48px;")
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(20, 0, 20, 0)

        self.view_title_lbl = QLabel("Dashboard Overview")
        self.view_title_lbl.setStyleSheet("color: #F8FAFC; font-size: 15px; font-weight: bold;")

        env_status = "📦 Portable EXE Mode" if is_frozen() else "🐍 Python Dev Mode"
        env_lbl = QLabel(env_status)
        env_lbl.setStyleSheet("color: #00E5FF; font-size: 12px; font-weight: 500;")

        tb_layout.addWidget(self.view_title_lbl)
        tb_layout.addStretch()
        tb_layout.addWidget(env_lbl)

        right_layout.addWidget(top_bar)

        # QStackedWidget for Views
        self.stacked_widget = QStackedWidget()

        self._views["dashboard"] = DashboardView()
        self._views["query"] = QueryView(service=self.service)
        self._views["waf"] = WAFAnalysisView()
        self._views["origin"] = OriginFinderView(service=self.service.origin_ip_service)
        self._views["reports"] = ReportsView()
        self._views["logs"] = LogsView()
        self._views["settings"] = SettingsView()

        # Connect WAF & Origin Analysis signals to IP investigation switch
        self._views["waf"].investigate_ip_requested.connect(self._handle_waf_investigate_request)
        self._views["origin"].investigate_ip_requested.connect(self._handle_origin_investigate_request)

        for view_name, view_widget in self._views.items():
            self.stacked_widget.addWidget(view_widget)

        right_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(right_container, 1)

        # 3. Bottom Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("IP Sentinel AI v5.0.0-phase5 | Ready.")

        # Developer Attribution (Right Bottom)
        self.dev_label = QLabel("Developed By: Vivek Nigam")
        self.dev_label.setStyleSheet("color: #00E5FF; font-weight: bold; font-size: 11px; padding-right: 12px;")
        self.status_bar.addPermanentWidget(self.dev_label)

    def _handle_waf_investigate_request(self, target_ip: str, waf_analysis):
        """Handle request to investigate an IP selected in WAF Analysis view."""
        self.switch_view("query")
        query_view = self._views.get("query")
        if query_view and hasattr(query_view, "ip_input"):
            query_view.ip_input.setText(target_ip)
            query_view.current_waf_analysis = waf_analysis
            query_view.start_investigation()

    def _handle_origin_investigate_request(self, target_ip: str):
        """Handle request to investigate an IP discovered in Origin Finder view."""
        self.switch_view("query")
        query_view = self._views.get("query")
        if query_view and hasattr(query_view, "ip_input"):
            query_view.ip_input.setText(target_ip)
            query_view.start_investigation()

    @Slot(str)
    def switch_view(self, view_name: str):
        """Switch active view on QStackedWidget and update title."""
        if view_name in self._views:
            widget = self._views[view_name]
            self.stacked_widget.setCurrentWidget(widget)
            
            # Sync sidebar state if navigation triggered via SignalBus
            if self.sidebar.active_view != view_name:
                self.sidebar.select_view(view_name)

            titles = {
                "dashboard": "Security Operations Dashboard",
                "query": "IP Threat Intelligence Investigation",
                "waf": "WAF Behavioral & Attack Analysis Engine",
                "origin": "Origin IP & CDN Discovery Engine",
                "reports": "Forensic Report Generation Engine",
                "logs": "Live System Audit Logs",
                "settings": "Settings & Threat Intelligence Providers",
            }
            self.view_title_lbl.setText(titles.get(view_name, "IP Sentinel AI"))
            self.status_bar.showMessage(f"Active View: {view_name.upper()}")
