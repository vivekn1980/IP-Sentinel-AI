"""Unit tests for IP validation and sanitization utilities."""

from ip_sentinel.core.ip_utils import is_valid_ip, validate_and_classify_ip, validate_cidr


def test_valid_ipv4_classification():
    res = validate_and_classify_ip("185.220.101.5")
    assert res.is_valid is True
    assert res.version == 4
    assert res.normalized_ip == "185.220.101.5"
    assert res.is_private is False
    assert res.is_loopback is False


def test_private_ipv4_classification():
    res = validate_and_classify_ip("192.168.1.1")
    assert res.is_valid is True
    assert res.is_private is True


def test_loopback_ipv4_classification():
    res = validate_and_classify_ip("127.0.0.1")
    assert res.is_valid is True
    assert res.is_loopback is True


def test_valid_ipv6_classification():
    res = validate_and_classify_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res.is_valid is True
    assert res.version == 6


def test_invalid_ip_formats():
    assert is_valid_ip("256.256.256.256") is False
    assert is_valid_ip("1.1.1.1; rm -rf /") is False
    assert is_valid_ip("not_an_ip") is False
    assert is_valid_ip("") is False


def test_cidr_validation():
    valid, norm, err = validate_cidr("192.168.0.0/24")
    assert valid is True
    assert norm == "192.168.0.0/24"
    assert err is None

    invalid, norm, err = validate_cidr("invalid_cidr/33")
    assert invalid is False
    assert err is not None
