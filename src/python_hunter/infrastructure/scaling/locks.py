"""Distributed Locking with TTL expiration and recovery."""

import threading
import time
from dataclasses import dataclass, field


@dataclass
class DistributedLock:
    """Distributed Lock metadata representation."""

    resource_name: str
    owner_id: str
    acquired_at: float
    ttl_seconds: int

    @property
    def is_expired(self) -> bool:
        return time.time() >= (self.acquired_at + self.ttl_seconds)


class LockManager:
    """Thread-safe lock manager with worker crash auto-recovery on TTL expiration."""

    def __init__(self) -> None:
        self._locks: dict[str, DistributedLock] = {}
        self._lock = threading.Lock()

    def acquire_lock(self, resource_name: str, owner_id: str, ttl_seconds: int = 30) -> bool:
        with self._lock:
            existing = self._locks.get(resource_name)
            if existing:
                if existing.is_expired:
                    # Lock owner died or timed out -> Recover lock safely
                    pass
                elif existing.owner_id == owner_id:
                    return True
                else:
                    return False

            self._locks[resource_name] = DistributedLock(
                resource_name=resource_name,
                owner_id=owner_id,
                acquired_at=time.time(),
                ttl_seconds=ttl_seconds,
            )
            return True

    def release_lock(self, resource_name: str, owner_id: str) -> bool:
        with self._lock:
            existing = self._locks.get(resource_name)
            if existing and existing.owner_id == owner_id:
                del self._locks[resource_name]
                return True
            return False
