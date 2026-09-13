"""Global PySide6 SignalBus singleton for application-wide event broadcasting."""

from PySide6.QtCore import QObject, Signal


class SignalBus(QObject):
    """Central signal hub for decoupled cross-component UI and service updates."""

    # Navigation Signals
    navigation_requested = Signal(str)  # Target view name (e.g. "query", "reports")

    # Investigation Signals
    investigation_started = Signal(str)  # target_ip
    investigation_progress = Signal(int, str)  # percentage, step_description
    investigation_completed = Signal(object)  # IPIntelResult object
    investigation_failed = Signal(str, str)  # target_ip, error_message

    # Report Signals
    report_generation_started = Signal(str)  # report_type ("HTML", "PDF")
    report_generation_completed = Signal(str, str)  # report_type, file_path
    report_generation_failed = Signal(str, str)  # report_type, error_message

    # Config Signals
    config_changed = Signal()
    provider_status_changed = Signal(str, str)  # provider_name, status_str

    _instance = None

    @classmethod
    def instance(cls) -> "SignalBus":
        """Singleton accessor for SignalBus instance."""
        if cls._instance is None:
            cls._instance = SignalBus()
        return cls._instance
