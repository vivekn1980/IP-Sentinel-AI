"""Unit tests for CacheManager."""

import time
from ip_sentinel.core.cache import CacheManager


def test_cache_set_and_get(tmp_path):
    mgr = CacheManager(cache_dir=tmp_path, default_ttl=60)
    mgr.set("test_key_1", {"foo": "bar"})

    res = mgr.get("test_key_1")
    assert res == {"foo": "bar"}


def test_cache_expiration(tmp_path):
    mgr = CacheManager(cache_dir=tmp_path, default_ttl=1)
    mgr.set("expiring_key", "val", ttl_seconds=1)

    assert mgr.get("expiring_key") == "val"
    time.sleep(1.1)
    assert mgr.get("expiring_key") is None


def test_cache_clear(tmp_path):
    mgr = CacheManager(cache_dir=tmp_path, default_ttl=60)
    mgr.set("key_a", "val_a")
    mgr.set("key_b", "val_b")

    mgr.clear()
    assert mgr.get("key_a") is None
    assert mgr.get("key_b") is None
