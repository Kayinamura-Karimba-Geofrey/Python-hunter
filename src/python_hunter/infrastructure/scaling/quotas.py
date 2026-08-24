"""Resource Quota Manager and Tenant Capacity Enforcement."""

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResourceQuota:
    """Resource quota limits for an Organization tenant."""

    organization_id: str
    max_concurrent_scans: int = 5
    max_daily_scans: int = 500
    max_repositories: int = 100
    max_api_requests_per_minute: int = 1000
    max_storage_bytes: int = 10 * 1024 * 1024 * 1024  # 10 GB


class QuotaExceededError(Exception):
    """Raised when tenant exceeds resource quota limits."""

    pass


class QuotaManager:
    """Thread-safe Resource Quota Manager with atomic reservation."""

    def __init__(self) -> None:
        self._quotas: dict[str, ResourceQuota] = {}
        self._active_scans: dict[str, int] = {}
        self._daily_scans: dict[str, int] = {}
        self._lock = threading.Lock()

    def set_quota(self, quota: ResourceQuota) -> None:
        with self._lock:
            self._quotas[quota.organization_id] = quota

    def get_quota(self, organization_id: str) -> ResourceQuota:
        with self._lock:
            return self._quotas.get(organization_id, ResourceQuota(organization_id=organization_id))

    def reserve_scan_slot(self, organization_id: str) -> bool:
        """Reserve scan slot under quota rules."""
        with self._lock:
            quota = self.get_quota(organization_id)
            current_active = self._active_scans.get(organization_id, 0)
            current_daily = self._daily_scans.get(organization_id, 0)

            if current_active >= quota.max_concurrent_scans:
                raise QuotaExceededError(f"Organization {organization_id} exceeded max concurrent scans limit ({quota.max_concurrent_scans}).")

            if current_daily >= quota.max_daily_scans:
                raise QuotaExceededError(f"Organization {organization_id} exceeded max daily scans limit ({quota.max_daily_scans}).")

            self._active_scans[organization_id] = current_active + 1
            self._daily_scans[organization_id] = current_daily + 1
            return True

    def release_scan_slot(self, organization_id: str) -> None:
        """Release active scan slot upon job completion."""
        with self._lock:
            current_active = self._active_scans.get(organization_id, 0)
            if current_active > 0:
                self._active_scans[organization_id] = current_active - 1
