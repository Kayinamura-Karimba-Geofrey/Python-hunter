"""Bulkhead Pattern implementation isolating specialized worker pools."""

import threading
from enum import Enum


class WorkerPoolType(str, Enum):
    """Specialized worker pool classifications."""

    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    CONTAINERS = "CONTAINERS"
    INTEGRATIONS = "INTEGRATIONS"


class BulkheadManager:
    """Bulkhead Isolation Manager preventing one workload type from exhausting platform capacity."""

    DEFAULT_CAPACITIES = {
        WorkerPoolType.SAST: 10,
        WorkerPoolType.SCA: 10,
        WorkerPoolType.SECRETS: 15,
        WorkerPoolType.INFRASTRUCTURE: 8,
        WorkerPoolType.CONTAINERS: 5,
        WorkerPoolType.INTEGRATIONS: 20,
    }

    def __init__(self) -> None:
        self._active_workers: dict[WorkerPoolType, int] = {pool: 0 for pool in WorkerPoolType}
        self._lock = threading.Lock()

    def acquire_slot(self, pool: WorkerPoolType) -> bool:
        with self._lock:
            max_capacity = self.DEFAULT_CAPACITIES.get(pool, 5)
            current = self._active_workers.get(pool, 0)
            if current < max_capacity:
                self._active_workers[pool] = current + 1
                return True
            return False

    def release_slot(self, pool: WorkerPoolType) -> None:
        with self._lock:
            current = self._active_workers.get(pool, 0)
            if current > 0:
                self._active_workers[pool] = current - 1
