"""Security Incident model and Security Incident Correlation Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.operations.alerts import SecurityAlert


class IncidentStatus(str, Enum):
    """Lifecycle states for Security Incidents."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


@dataclass
class IncidentTimelineEntry:
    """Timeline audit entry for incident lifecycle."""

    timestamp: datetime
    event_type: str
    description: str
    actor: str = "system"


@dataclass
class SecurityIncident:
    """Security Incident grouping correlated alerts, findings, attack paths, and assets."""

    incident_id: str
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    alerts: list[SecurityAlert] = field(default_factory=list)
    affected_repositories: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    attack_path_ids: list[str] = field(default_factory=list)
    root_cause: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    timeline: list[IncidentTimelineEntry] = field(default_factory=list)


class IncidentCorrelationEngine:
    """Correlates multiple security alerts and findings into unified Security Incidents."""

    def __init__(self) -> None:
        self.incidents: dict[str, SecurityIncident] = {}

    def correlate_alerts(self, alerts: list[SecurityAlert]) -> list[SecurityIncident]:
        """Group related security alerts by repository or attack surface into single incidents."""
        groups: dict[str, list[SecurityAlert]] = {}
        for a in alerts:
            key = a.repository
            if key not in groups:
                groups[key] = []
            groups[key].append(a)

        for repo, repo_alerts in groups.items():
            if not repo_alerts:
                continue

            # Highest severity in group
            top_severity = max(repo_alerts, key=lambda x: x.severity.weight).severity
            inc_id = f"INC-{repo.replace('/', '-')}"

            if inc_id in self.incidents:
                inc = self.incidents[inc_id]
                inc.alerts = repo_alerts
                inc.severity = top_severity
            else:
                inc = SecurityIncident(
                    incident_id=inc_id,
                    title=f"Correlated Security Incident on {repo}",
                    severity=top_severity,
                    alerts=repo_alerts,
                    affected_repositories=[repo],
                    affected_assets=[a.asset for a in repo_alerts if a.asset],
                    root_cause=f"Multiple correlated alerts ({len(repo_alerts)}) detected on repository {repo}.",
                    timeline=[
                        IncidentTimelineEntry(
                            timestamp=datetime.now(timezone.utc),
                            event_type="INCIDENT_CREATED",
                            description=f"Automated incident created from {len(repo_alerts)} security alerts.",
                        )
                    ],
                )
                self.incidents[inc_id] = inc

        return list(self.incidents.values())
