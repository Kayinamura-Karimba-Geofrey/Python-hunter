"""Health and Readiness Endpoint Telemetry Evaluator."""

from dataclasses import dataclass
from enum import Enum


class HealthState(str, Enum):
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"


@dataclass
class DependencyHealthStatus:
    """Dependency health snapshot."""

    database: HealthState = HealthState.UP
    queue: HealthState = HealthState.UP
    cache: HealthState = HealthState.UP
    object_storage: HealthState = HealthState.UP
    event_bus: HealthState = HealthState.UP

    @property
    def is_healthy(self) -> bool:
        return all(s == HealthState.UP for s in [self.database, self.queue, self.cache, self.object_storage, self.event_bus])
