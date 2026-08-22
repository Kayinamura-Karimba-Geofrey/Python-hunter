"""Finding Domain Model."""

from dataclasses import dataclass, field
import hashlib
import uuid
from typing import Any
from python_hunter.domain.common.enums import (
    Category,
    Confidence,
    ExposureType,
    FindingLifecycleState,
    FindingStatus,
    ReachabilityType,
    Severity,
    VerificationStatus,
    VerificationConfidence,
)
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.exceptions.base import ValidationError


@dataclass
class Finding:
    """Actionable security risk finding identified during analysis."""

    rule_id: str
    severity: Severity
    confidence: Confidence
    category: Category
    title: str
    description: str
    file_path: str
    location: Location | None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    risk_score: float = 0.0
    source: str = ""
    sink: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    exposure: ExposureType = ExposureType.UNKNOWN
    reachability: ReachabilityType = ReachabilityType.UNKNOWN
    lifecycle_state: FindingLifecycleState = FindingLifecycleState.NEW
    attack_path_id: str | None = None
    related_findings: list[str] = field(default_factory=list)
    secondary_evidence: list[str] = field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.NOT_TESTED
    verification_confidence: VerificationConfidence = VerificationConfidence.LOW
    verification_timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValidationError("rule_id cannot be empty")
        if not self.file_path:
            raise ValidationError("file_path cannot be empty")
        if not self.title:
            raise ValidationError("title cannot be empty")
        
        if not self.fingerprint:
            self.fingerprint = self.generate_fingerprint()

    def generate_fingerprint(self) -> str:
        """Compute stable SHA-256 fingerprint for tracking finding across commits."""
        line = self.location.line_start if self.location else 0
        raw = f"{self.rule_id}:{self.file_path}:{line}:{self.source}:{self.sink}:{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def update_status(self, new_status: FindingStatus) -> None:
        """Transition finding status (e.g. ACKNOWLEDGED, FALSE_POSITIVE, RESOLVED)."""
        self.status = new_status

