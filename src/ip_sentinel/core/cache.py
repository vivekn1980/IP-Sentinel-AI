"""Simple thread-safe JSON file and memory cache manager for IP Sentinel AI.

Caches passive network lookup responses (RDAP, GeoIP, DNS) with configurable TTL.
Does not use an external database server or SQLite.
"""

import json
import logging
import time
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from ip_sentinel.core.path_utils import get_app_data_dir

logger = logging.getLogger("ip_sentinel.cache")


class CacheManager:
    """Thread-safe TTL file-backed cache manager."""

    _instance: Optional["CacheManager"] = None
    _lock = threading.Lock()

    def __new__(cls, cache_dir: Optional[Path] = None, default_ttl: int = 3600) -> "CacheManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, cache_dir: Optional[Path] = None, default_ttl: int = 3600):
        if getattr(self, "_initialized", False):
            return

        self.cache_dir = cache_dir or (get_app_data_dir() / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._rw_lock = threading.Lock()
        self._initialized = True

    def _get_file_path(self, key: str) -> Path:
        # Sanitize key for filesystem safe filename
        safe_key = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in key)
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached value if present and not expired."""
        now = time.time()
        with self._rw_lock:
            # 1. Check in-memory cache
            if key in self._memory_cache:
                entry = self._memory_cache[key]
                if entry["expires_at"] > now:
                    logger.debug(f"Cache HIT (memory) for key '{key}'")
                    return entry["data"]
                else:
                    del self._memory_cache[key]

            # 2. Check disk cache file
            file_path = self._get_file_path(key)
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    expires_at = data.get("expires_at", 0)
                    if expires_at > now:
                        val = data.get("value")
                        self._memory_cache[key] = {"expires_at": expires_at, "data": val}
                        logger.debug(f"Cache HIT (disk) for key '{key}'")
                        return val
                    else:
                        file_path.unlink(missing_ok=True)
                except Exception as err:
                    logger.warning(f"Error reading cache file {file_path}: {err}")

        logger.debug(f"Cache MISS for key '{key}'")
        return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Store a value in cache with TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + ttl

        with self._rw_lock:
            self._memory_cache[key] = {"expires_at": expires_at, "data": value}
            file_path = self._get_file_path(key)
            try:
                temp_path = file_path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump({"expires_at": expires_at, "value": value}, f)
                if temp_path.exists():
                    temp_path.replace(file_path)
            except Exception as err:
                logger.warning(f"Failed to persist cache entry to {file_path}: {err}")

    def clear(self) -> None:
        """Purge all cached entries."""
        with self._rw_lock:
            self._memory_cache.clear()
            for file_path in self.cache_dir.glob("*.json"):
                try:
                    file_path.unlink(missing_ok=True)
                except Exception:
                    pass
