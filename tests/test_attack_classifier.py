"""Unit tests for AttackClassifier rule evaluation and confidence scoring."""

from ip_sentinel.models.waf_behavior import AttackClassification, WAFIPAnalysis
from ip_sentinel.services.attack_classifier import AttackClassifier


def test_attack_classifier_web_scanner():
    classifier = AttackClassifier()
    analysis = WAFIPAnalysis(
        source_ip="198.51.100.45",
        total_requests=6,
        duration_seconds=5.0,
        unique_uri_count=6,
        config_file_hits=2,
        admin_endpoint_hits=2,
        pct_404=83.3,
        pct_4xx=100.0,
        dominant_ua="python-requests/2.31.0",
        dominant_ua_pct=100.0,
    )
    cls, conf, supp, contr, lim, fp = classifier.classify(analysis)
    assert cls == AttackClassification.WEB_SCANNER
    assert conf >= 85
    assert len(supp) >= 2


def test_attack_classifier_credential_attack():
    classifier = AttackClassifier()
    analysis = WAFIPAnalysis(
        source_ip="192.0.2.100",
        total_requests=5,
        duration_seconds=4.0,
        auth_endpoint_hits=5,
        pct_4xx=100.0,
        get_post_ratio=0.0,
        method_distribution={"POST": 5},
        dominant_ua="CredBot/1.0",
        dominant_ua_pct=100.0,
    )
    cls, conf, supp, contr, lim, fp = classifier.classify(analysis)
    assert cls == AttackClassification.CREDENTIAL_ATTACK
    assert conf >= 80


def test_attack_classifier_http_flood():
    classifier = AttackClassifier()
    analysis = WAFIPAnalysis(
        source_ip="198.51.100.99",
        total_requests=10,
        duration_seconds=0.5,
        peak_req_per_sec=20.0,
        peak_req_per_min=1200.0,
        is_bursty=True,
        pct_2xx=100.0,
        repeated_uri_ratio=100.0,
    )
    cls, conf, supp, contr, lim, fp = classifier.classify(analysis)
    assert cls == AttackClassification.HTTP_FLOOD
    assert conf >= 75
    assert len(contr) >= 1  # 2xx response contradiction note


def test_attack_classifier_normal_client():
    classifier = AttackClassifier()
    analysis = WAFIPAnalysis(
        source_ip="203.0.113.15",
        total_requests=10,
        duration_seconds=30.0,
        peak_req_per_sec=0.5,
        pct_2xx=90.0,
        pct_404=0.0,
        unique_uri_count=5,
        config_file_hits=0,
        admin_endpoint_hits=0,
    )
    cls, conf, supp, contr, lim, fp = classifier.classify(analysis)
    assert cls == AttackClassification.NORMAL_CLIENT
    assert conf >= 80


def test_attack_classifier_unknown_insufficient():
    classifier = AttackClassifier()
    analysis = WAFIPAnalysis(source_ip="127.0.0.1", total_requests=1)
    cls, conf, supp, contr, lim, fp = classifier.classify(analysis)
    assert cls == AttackClassification.UNKNOWN
    assert conf <= 40
    assert len(lim) >= 1
