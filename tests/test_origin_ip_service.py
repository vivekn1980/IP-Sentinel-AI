"""Unit and integration tests for OriginIPService and data models."""

from ip_sentinel.models.origin_finder import (
    CDNCheckResult,
    FaviconHashResult,
    OriginCandidate,
    OriginDiscoveryResult,
)
from ip_sentinel.services.origin_ip_service import OriginIPService, mmh3_hash_bytes


def test_domain_extraction():
    svc = OriginIPService()
    assert svc.extract_domain("https://www.example.com/api/v1") == "www.example.com"
    assert svc.extract_domain("http://sub.domain.co.uk") == "sub.domain.co.uk"
    assert svc.extract_domain("example.com") == "example.com"


def test_cdn_cidr_checking():
    svc = OriginIPService()
    # Cloudflare IP
    cf_res = svc.check_cdn("104.16.1.1")
    assert cf_res.is_cdn is True
    assert cf_res.provider == "Cloudflare"

    # AWS CloudFront IP
    cfn_res = svc.check_cdn("13.32.1.1")
    assert cfn_res.is_cdn is True
    assert cfn_res.provider == "AWS CloudFront"

    # Tata Communications (BitGravity) IP
    tata_res = svc.check_cdn("64.185.167.102")
    assert tata_res.is_cdn is True
    assert tata_res.provider == "Tata Communications (BitGravity CDN)"

    # Non-CDN Public IP
    direct_res = svc.check_cdn("1.1.1.1")  # Note: 1.1.1.1 is Cloudflare DNS, but not in CDN_CIDRS list in our mapping
    assert direct_res.ip == "1.1.1.1"


def test_email_header_parsing():
    svc = OriginIPService()
    sample_headers = """
    Received: from mail.targetsite.com (mail.targetsite.com [93.184.216.34])
        by mx.google.com with ESMTPS id xyz
        for <analyst@example.com>;
    Received: from 10.0.0.1 (localhost [127.0.0.1])
    """
    res = svc.parse_email_headers(sample_headers)
    assert len(res.extracted_ips) >= 3
    assert "93.184.216.34" in res.candidate_origin_ips
    assert "10.0.0.1" not in res.candidate_origin_ips  # Private IP filtered
    assert "127.0.0.1" not in res.candidate_origin_ips  # Loopback IP filtered


def test_mmh3_hash_fallback():
    # Test MurmurHash3 calculation
    content = b"aW1wb3J0IGJhc2U2NA==\n"
    h_val = mmh3_hash_bytes(content)
    assert isinstance(h_val, int)


def test_origin_discovery_run():
    svc = OriginIPService()
    res = svc.run_discovery("example.com")
    assert isinstance(res, OriginDiscoveryResult)
    assert res.target_domain == "example.com"
    assert isinstance(res.resolved_ips, list)
    assert res.execution_time_seconds >= 0


def test_target_host_port_parsing():
    svc = OriginIPService()
    assert svc._parse_target_host_port("https://example.com/api/test") == ("example.com", 443)
    assert svc._parse_target_host_port("https://backend.local:8443/status") == ("backend.local", 8443)
    assert svc._parse_target_host_port("1.1.1.1:443") == ("1.1.1.1", 443)
    assert svc._parse_target_host_port("192.168.1.100:9443") == ("192.168.1.100", 9443)
    assert svc._parse_target_host_port("cloudflare.com") == ("cloudflare.com", 443)


def test_cert_date_parsing():
    svc = OriginIPService()
    dt = svc._parse_cert_date("Dec 21 19:20:01 2026 GMT")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 12
    assert dt.day == 21

    dt2 = svc._parse_cert_date("Jan  5 10:00:00 2025 UTC")
    assert dt2 is not None
    assert dt2.year == 2025
    assert dt2.month == 1
    assert dt2.day == 5


def test_cert_inspection_unreachable_target():
    svc = OriginIPService()
    res = svc.inspect_certificate("127.0.0.1", port=59999, timeout=0.5)
    assert res.status == "ERROR"
    assert res.error is not None


def test_cert_inspection_live_target():
    # Test on Cloudflare Public DNS IP (1.1.1.1)
    svc = OriginIPService()
    res = svc.inspect_certificate("1.1.1.1", port=443, timeout=5.0)
    # If network is available, it returns VALID; if restricted, returns ERROR
    if res.status != "ERROR":
        assert res.status in ["VALID", "EXPIRING_SOON"]
        assert len(res.common_name) > 0
        assert len(res.sans) > 0
        assert len(res.sha256_fingerprint) > 0
        assert res.days_remaining > 0


def test_scan_ports_and_banners_closed():
    res = OriginIPService.scan_ports_and_banners("127.0.0.1", [59998, 59999], timeout=0.3)
    assert res.ip == "127.0.0.1"
    assert len(res.open_ports) == 2
    assert res.open_ports[0].port == 59998
    assert res.open_ports[0].state in ["CLOSED", "FILTERED"]


def test_scan_ports_live_cloudflare():
    res = OriginIPService.scan_ports_and_banners("1.1.1.1", [80, 443], timeout=3.0)
    assert res.ip == "1.1.1.1"
    assert len(res.open_ports) == 2
    for p in res.open_ports:
        if p.state == "OPEN":
            assert "cloudflare" in p.banner.lower()


def test_fetch_passive_dns_history_structure():
    records = OriginIPService.fetch_passive_dns_history("example.com")
    assert isinstance(records, list)
    for r in records:
        assert len(r.domain) > 0
        assert len(r.ip) > 0
        assert len(r.source) > 0
