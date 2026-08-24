"""Platform Metrics Collector for Telemetry and Observability."""

import threading
from dataclasses import dataclass, field


@dataclass
class TelemetryMetrics:
    """Platform Operational Metrics Container."""

    api_requests_total: int = 0
    job_queue_depth: int = 0
    worker_utilization_ratio: float = 0.0
    cache_hit_rate: float = 1.0
    critical_findings_count: int = 0
    unresolved_vulnerabilities_count: int = 0


class MetricsCollector:
    """Thread-safe telemetry metrics collector."""

    def __init__(self) -> None:
        self.metrics = TelemetryMetrics()
        self._lock = threading.Lock()

    def record_api_request(self) -> None:
        with self._lock:
            self.metrics.api_requests_total += 1

    def update_queue_depth(self, depth: int) -> None:
        with self._lock:
            self.metrics.job_queue_depth = depth
