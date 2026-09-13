"""Unit tests for WAF log parsers (CSV, JSON, NDJSON)."""

import os
import pytest

from ip_sentinel.parsers.csv_parser import CSVWAFParser
from ip_sentinel.parsers.json_parser import JSONWAFParser


def test_csv_waf_parser_clean():
    parser = CSVWAFParser()
    csv_data = """timestamp,source_ip,http_method,uri_path,user_agent,status_code,waf_rule,waf_action
2026-09-13T10:00:01Z,203.0.113.15,GET,/,Mozilla/5.0,200,NONE,ALLOW
2026-09-13T10:00:05Z,203.0.113.15,POST,/api/cart,Mozilla/5.0,200,NONE,ALLOW
"""
    events = parser.parse_content(csv_data)
    assert len(events) == 2
    assert events[0].source_ip == "203.0.113.15"
    assert events[0].http_method == "GET"
    assert events[0].uri_path == "/"
    assert events[0].status_code == 200
    assert events[1].http_method == "POST"
    assert events[1].uri_path == "/api/cart"


def test_csv_waf_parser_missing_fields_and_malformed():
    parser = CSVWAFParser()
    csv_data = """ip,method,url,status
invalid-ip,GET,/test,abc
198.51.100.1,POST,/login,401
"""
    events = parser.parse_content(csv_data)
    assert len(events) == 2
    assert events[0].source_ip == "0.0.0.0"
    assert events[0].status_code is None
    assert events[1].source_ip == "198.51.100.1"
    assert events[1].status_code == 401


def test_json_waf_parser_array():
    parser = JSONWAFParser()
    json_data = """[
        {"timestamp": "2026-09-13T10:00:00Z", "source_ip": "198.51.100.45", "http_method": "GET", "uri_path": "/.env", "status_code": 404},
        {"timestamp": "2026-09-13T10:00:01Z", "source_ip": "198.51.100.45", "http_method": "GET", "uri_path": "/admin", "status_code": 403}
    ]"""
    events = parser.parse_content(json_data)
    assert len(events) == 2
    assert events[0].source_ip == "198.51.100.45"
    assert events[0].uri_path == "/.env"
    assert events[0].status_code == 404
    assert events[1].uri_path == "/admin"
    assert events[1].status_code == 403


def test_json_waf_parser_ndjson():
    parser = JSONWAFParser()
    ndjson_data = """{"client_ip": "192.0.2.1", "method": "GET", "uri": "/home", "status": 200}
{"client_ip": "192.0.2.1", "method": "POST", "uri": "/login", "status": 401}
"""
    events = parser.parse_content(ndjson_data)
    assert len(events) == 2
    assert events[0].source_ip == "192.0.2.1"
    assert events[0].uri_path == "/home"
    assert events[1].uri_path == "/login"


def test_json_waf_parser_fixture_file():
    parser = JSONWAFParser()
    fixture_path = os.path.join("resources", "fixtures", "scanner_traffic.json")
    if os.path.exists(fixture_path):
        events = parser.parse_file(fixture_path)
        assert len(events) >= 5
        assert events[0].source_ip == "198.51.100.45"
