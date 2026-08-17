"""Finding Domain Model."""

from dataclasses import dataclass, field
import hashlib
import uuid
from python_hunter.domain.common.enums import Category, Confidence, FindingStatus, Severity
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
    location: Location
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
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
        """Compute SHA-256 fingerprint for tracking finding across commits."""
        raw = f"{self.file_path}:{self.rule_id}:{self.location.line_start}:{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def update_status(self, new_status: FindingStatus) -> None:
        """Transition finding status (e.g. ACKNOWLEDGED, FALSE_POSITIVE, RESOLVED)."""
        self.status = new_status
