"""Remediation Queue, Remediation Campaign, SLA and MTTR tracking engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.intelligence.models import VulnerabilityRecord


class RemediationStatus(str, Enum):
    """Remediation task workflow states."""

    ASSIGNED = "ASSIGNED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"


@dataclass
class RemediationItem:
    """Task item in Remediation Queue."""

    id: str
    vulnerability_id: str
    repository: str
    severity: Severity
    risk_score: float
    is_reachable: bool = False
    is_verified: bool = False
    epss_score: float = 0.0
    sla_due_date: datetime | None = None
    owner: str | None = None
    status: RemediationStatus = RemediationStatus.ASSIGNED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None

    @property
    def is_overdue(self) -> bool:
        if self.status in (RemediationStatus.FIXED, RemediationStatus.VERIFIED):
            return False
        if self.sla_due_date and datetime.now(timezone.utc) > self.sla_due_date:
            return True
        return False

    @property
    def rank_score(self) -> float:
        """Calculate dynamic priority ranking score."""
        score = self.risk_score
        if self.is_verified:
            score += 40.0
        if self.is_reachable:
            score += 30.0
        score += self.epss_score * 20.0
        if self.is_overdue:
            score += 15.0
        return round(score, 2)


@dataclass
class RemediationCampaign:
    """Grouped remediation campaign across repositories."""

    campaign_id: str
    title: str
    target_package: str
    target_version: str
    items: list[RemediationItem] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.items)

    @property
    def fixed_count(self) -> int:
        return sum(1 for i in self.items if i.status in (RemediationStatus.FIXED, RemediationStatus.VERIFIED))


class RemediationQueueManager:
    """Manages prioritizing remediation issues, SLA tracking, MTTR calculation, and campaigns."""

    DEFAULT_SLA_DAYS = {
        Severity.CRITICAL: 7,
        Severity.HIGH: 30,
        Severity.MEDIUM: 60,
        Severity.LOW: 90,
        Severity.INFO: 180,
    }

    def __init__(self) -> None:
        self.items: dict[str, RemediationItem] = {}
        self.campaigns: dict[str, RemediationCampaign] = {}

    def add_item(self, item: RemediationItem) -> None:
        if not item.sla_due_date:
            days = self.DEFAULT_SLA_DAYS.get(item.severity, 30)
            item.sla_due_date = datetime.now(timezone.utc)
            # Add days safely
            import datetime as dt
            item.sla_due_date = item.sla_due_date + dt.timedelta(days=days)
        self.items[item.id] = item

    def get_ranked_queue(self) -> list[RemediationItem]:
        return sorted(self.items.values(), key=lambda x: x.rank_score, reverse=True)

    def calculate_mttr(self) -> dict[str, float]:
        """Calculate Mean Time To Remediation (MTTR) in days."""
        resolved = [i for i in self.items.values() if i.resolved_at and i.created_at]
        if not resolved:
            return {"overall_days": 0.0, "critical_days": 0.0, "high_days": 0.0}

        total_days = sum((i.resolved_at - i.created_at).total_seconds() / 86400.0 for i in resolved)
        overall_mttr = total_days / len(resolved)

        crit_resolved = [i for i in resolved if i.severity == Severity.CRITICAL]
        crit_mttr = (
            sum((i.resolved_at - i.created_at).total_seconds() / 86400.0 for i in crit_resolved) / len(crit_resolved)
            if crit_resolved
            else 0.0
        )

        return {
            "overall_days": round(overall_mttr, 2),
            "critical_days": round(crit_mttr, 2),
        }
