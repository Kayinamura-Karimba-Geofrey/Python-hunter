"""Domain Enums for Python Hunter."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability and finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        """Numeric weight for risk scoring calculations."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.5,
        }
        return weights[self]


class Confidence(str, Enum):
    """Detection confidence levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def multiplier(self) -> float:
        """Multiplier for risk scoring calculations."""
        multipliers = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.8,
            Confidence.LOW: 0.5,
        }
        return multipliers[self]


class ScanStatus(str, Enum):
    """Scan lifecycle execution states."""

    PENDING = "PENDING"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        """Check if the scan state is terminal (cannot transition further)."""
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED)


class FindingStatus(str, Enum):
    """Finding lifecycle triage states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class Category(str, Enum):
    """Security finding categories."""

    CODE_INJECTION = "CODE_INJECTION"
    SECRET_LEAK = "SECRET_LEAK"
    VULNERABLE_DEPENDENCY = "VULNERABLE_DEPENDENCY"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    GIT_RISK = "GIT_RISK"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    OTHER = "OTHER"
