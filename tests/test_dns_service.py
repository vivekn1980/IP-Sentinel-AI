"""Unit tests for DNSService."""

from unittest.mock import MagicMock, patch
from ip_sentinel.models.threat_intel import DataStatus
from ip_sentinel.services.dns_service import DNSService


@patch("dns.resolver.Resolver.resolve")
def test_dns_service_resolution(mock_resolve):
    def side_effect(qname, rtype):
        mock_rrset = MagicMock()
        if rtype == "PTR":
            r1 = MagicMock()
            r1.target = "one.one.one.one."
            mock_rrset.__iter__.return_value = [r1]
            return mock_rrset
        elif rtype == "A":
            r1 = MagicMock()
            r1.__str__.return_value = "1.1.1.1"
            mock_rrset.__iter__.return_value = [r1]
            return mock_rrset
        else:
            raise Exception("Record type not found")

    mock_resolve.side_effect = side_effect

    svc = DNSService(timeout=1.0)
    res = svc.resolve_all_records("1.1.1.1")

    assert res.status == DataStatus.AVAILABLE
    assert res.hostname == "one.one.one.one"
    assert "one.one.one.one" in res.ptr_records
    assert "1.1.1.1" in res.a_records
