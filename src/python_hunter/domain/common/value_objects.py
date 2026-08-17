"""Shared Domain Value Objects."""

from dataclasses import dataclass
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.exceptions.base import ValidationError


@dataclass(frozen=True)
class Location:
    """Source code line and column position."""

    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0

    def __post_init__(self) -> None:
        if self.line_start < 1:
            raise ValidationError("line_start must be >= 1", {"line_start": self.line_start})
        if self.line_end < self.line_start:
            raise ValidationError(
                "line_end cannot be less than line_start",
                {"line_start": self.line_start, "line_end": self.line_end},
            )


@dataclass(frozen=True)
class RiskScore:
    """Composite numeric risk score (0.0 to 10.0) and severity grade."""

    score: float
    grade: Severity

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 10.0):
            raise ValidationError("Risk score must be between 0.0 and 10.0", {"score": self.score})

    @classmethod
    def from_score(cls, score: float) -> "RiskScore":
        """Factory method deriving severity grade from numeric risk score."""
        bounded_score = round(max(0.0, min(10.0, score)), 2)
        if bounded_score >= 9.0:
            grade = Severity.CRITICAL
        elif bounded_score >= 7.0:
            grade = Severity.HIGH
        elif bounded_score >= 4.0:
            grade = Severity.MEDIUM
        elif bounded_score >= 1.0:
            grade = Severity.LOW
        else:
            grade = Severity.INFO
        return cls(score=bounded_score, grade=grade)
