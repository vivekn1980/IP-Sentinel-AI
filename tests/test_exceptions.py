"""Unit tests for custom exception hierarchy."""

import pytest
from ip_sentinel.core.exceptions import (
    ConfigError,
    IPSentinelError,
    NetworkError,
    ProviderError,
    ReportError,
    ValidationError,
)


def test_exception_hierarchy():
    assert issubclass(ConfigError, IPSentinelError)
    assert issubclass(ProviderError, IPSentinelError)
    assert issubclass(ReportError, IPSentinelError)
    assert issubclass(NetworkError, IPSentinelError)
    assert issubclass(ValidationError, IPSentinelError)


def test_exception_user_messages():
    err = ValidationError("Internal technical detail", user_message="Please enter a valid IP address.")
    assert str(err) == "Internal technical detail"
    assert err.user_message == "Please enter a valid IP address."
