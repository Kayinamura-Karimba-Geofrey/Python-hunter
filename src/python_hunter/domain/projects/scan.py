"""Scan Aggregate Root and Lifecycle State Machine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import uuid
from typing import ClassVar

from python_hunter.domain.common.enums import ScanStatus
from python_hunter.domain.common.value_objects import RiskScore
from python_hunter.domain.exceptions.base import ScanError
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.projects.project import Project


@dataclass
class Scan:
    """Scan aggregate root representing an execution run over a target Project."""

    project: Project
    commit_hash: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: ScanStatus = ScanStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None

    # Allowed state transitions matrix
    _VALID_TRANSITIONS: ClassVar[dict[ScanStatus, set[ScanStatus]]] = {
        ScanStatus.PENDING: {ScanStatus.INITIALIZING, ScanStatus.CANCELLED},
        ScanStatus.INITIALIZING: {ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCELLED},
        ScanStatus.RUNNING: {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED},
        ScanStatus.COMPLETED: set(),
        ScanStatus.FAILED: set(),
        ScanStatus.CANCELLED: set(),
    }

    def transition_to(self, new_status: ScanStatus, error_message: str | None = None) -> None:
        """Enforce strict lifecycle state transitions."""
        if new_status not in self._VALID_TRANSITIONS[self.status]:
            raise ScanError(
                f"Invalid scan status transition from {self.status.value} to {new_status.value}",
                {"current_status": self.status.value, "attempted_status": new_status.value},
            )

        self.status = new_status
        now = datetime.now(timezone.utc)

        if new_status == ScanStatus.INITIALIZING and self.started_at is None:
            self.started_at = now
        elif new_status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            self.completed_at = now
            if error_message:
                self.error_message = error_message

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the scan."""
        if self.status.is_terminal:
            raise ScanError("Cannot add findings to a scan in a terminal state", {"status": self.status.value})
        self.findings.append(finding)

    def calculate_risk_score(self) -> RiskScore:
        """Compute composite repository risk score based on findings."""
        if not self.findings:
            return RiskScore.from_score(0.0)

        total_weighted_risk = 0.0
        for f in self.findings:
            finding_risk = f.severity.weight * f.confidence.multiplier
            total_weighted_risk += finding_risk

        # Logarithmic saturation curve mapping aggregated weighted risk to 0.0-10.0 scale
        score = 10.0 * (1.0 - math.exp(-total_weighted_risk / 25.0))
        return RiskScore.from_score(score)
