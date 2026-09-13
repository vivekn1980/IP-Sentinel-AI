"""Unit tests for logger framework and secret redaction."""

from ip_sentinel.core.logger import QtSignalLogger, redact_secrets


def test_redact_secrets():
    msg = "Connecting to API with api_key: 'secret_token_12345678' and password=mysecretpass"
    redacted = redact_secrets(msg)
    assert "secret_token_12345678" not in redacted
    assert "***REDACTED***" in redacted


def test_qt_signal_logger_emission(qapp):
    handler = QtSignalLogger()
    received = []

    def log_slot(level, time_str, msg):
        received.append((level, msg))

    handler.emitter.log_emitted.connect(log_slot)
    
    import logging
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=1,
        msg="Test log message",
        args=(),
        exc_info=None,
    )
    handler.emit(record)

    assert len(received) == 1
    assert received[0][0] == "INFO"
    assert received[0][1] == "Test log message"
