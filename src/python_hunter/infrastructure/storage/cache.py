"""Distributed Cache Abstraction for Policy and RBAC Permissions."""

import threading
import time
from typing import Any


class CacheAbstraction:
    """Thread-safe distributed cache abstraction with Redis-compatible TTL invalidation."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        with self._lock:
            expire_at = time.time() + ttl_seconds
            self._store[key] = (value, expire_at)

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            val, expire_at = entry
            if time.time() >= expire_at:
                del self._store[key]
                return None
            return val

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)
