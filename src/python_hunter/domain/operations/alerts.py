"""Alert Engine, Alert Models, Deduplication, and Escalation Rules."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity


class AlertStatus(str, Enum):
    """Lifecycle states for Security Alerts."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AlertType(str, Enum):
    """Security alert types."""

    CRITICAL_VULNERABILITY = "critical_vulnerability"
    NEW_ATTACK_PATH = "new_attack_path"
    SECRET_EXPOSURE = "secret_exposure"
    PUBLIC_INFRASTRUCTURE = "public_infrastructure"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_REGRESSION = "security_regression"
    SLA_BREACH = "sla_breach"


@dataclass
class SecurityAlert:
    """Security Alert object representation."""

    alert_id: str
    severity: Severity
    alert_type: AlertType
    source: str
    repository: str
    finding_id: str | None = None
    attack_path_id: str | None = None
    asset: str | None = None
    title: str = ""
    description: str = ""
    status: AlertStatus = AlertStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def deduplication_key(self) -> str:
        """Key for alert grouping and deduplication to avoid alert fatigue."""
        return f"{self.alert_type.value}:{self.repository}:{self.finding_id or self.attack_path_id or self.asset or 'gen'}"


class AlertEngine:
    """Alert Management Engine with grouping, deduplication, prioritization, and escalation."""

    def __init__(self) -> None:
        self.alerts: dict[str, SecurityAlert] = {}
        self._dedup_index: dict[str, str] = {}  # dedup_key -> alert_id

    def create_or_deduplicate_alert(
        self,
        alert_id: str,
        severity: Severity,
        alert_type: AlertType,
        source: str,
        repository: str,
        title: str,
        description: str,
        finding_id: str | None = None,
        attack_path_id: str | None = None,
        asset: str | None = None,
    ) -> SecurityAlert:
        """Create new alert or update existing duplicate alert to eliminate fatigue."""
        temp_alert = SecurityAlert(
            alert_id=alert_id,
            severity=severity,
            alert_type=alert_type,
            source=source,
            repository=repository,
            title=title,
            description=description,
            finding_id=finding_id,
            attack_path_id=attack_path_id,
            asset=asset,
        )

        dedup_key = temp_alert.deduplication_key
        if dedup_key in self._dedup_index:
            existing_id = self._dedup_index[dedup_key]
            existing = self.alerts[existing_id]
            existing.updated_at = datetime.now(timezone.utc)
            # Update severity if escalated
            if severity.weight > existing.severity.weight:
                existing.severity = severity
            return existing

        self.alerts[alert_id] = temp_alert
        self._dedup_index[dedup_key] = alert_id
        return temp_alert

    def get_open_alerts(self) -> list[SecurityAlert]:
        """Return open alerts ordered by severity weight (descending)."""
        return sorted(
            [a for a in self.alerts.values() if a.status in (AlertStatus.OPEN, AlertStatus.INVESTIGATING)],
            key=lambda x: x.severity.weight,
            reverse=True,
        )

    def get_fatigue_metrics(self) -> dict[str, Any]:
        """Calculate alert fatigue metrics."""
        total = len(self.alerts)
        suppressed = sum(1 for a in self.alerts.values() if a.status == AlertStatus.SUPPRESSED)
        dedup_count = len(self.alerts) - len(self._dedup_index)
        return {
            "total_alerts_generated": total,
            "suppressed_alerts": suppressed,
            "deduplicated_alerts_prevented": max(0, dedup_count),
        }
