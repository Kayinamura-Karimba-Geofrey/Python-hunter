"""SecurityPlatformHealth monitoring workers, queues, DB, intelligence, and integrations."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class HealthState(str, Enum):
    """Platform health state."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass
class SecurityPlatformHealth:
    """System-wide health telemetry monitor."""

    status: HealthState = HealthState.HEALTHY
    worker_status: str = "RUNNING"
    active_workers_count: int = 4
    queue_depth: int = 0
    dead_letter_count: int = 0
    db_status: str = "CONNECTED"
    intelligence_freshness: str = "FRESH"
    github_integration_status: str = "OPERATIONAL"
    notification_providers_count: int = 1
    last_check_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "worker_status": self.worker_status,
            "active_workers_count": self.active_workers_count,
            "queue_depth": self.queue_depth,
            "dead_letter_count": self.dead_letter_count,
            "db_status": self.db_status,
            "intelligence_freshness": self.intelligence_freshness,
            "github_integration_status": self.github_integration_status,
            "notification_providers_count": self.notification_providers_count,
            "last_check_at": self.last_check_at.isoformat(),
        }
