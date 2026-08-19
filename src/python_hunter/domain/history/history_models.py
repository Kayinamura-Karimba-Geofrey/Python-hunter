"""Domain models for Historical Security Intelligence & Regression Engine."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding


class FindingLifecycle(str, Enum):
    """Lifecycle state of a finding across snapshots."""

    NEW = "NEW"
    EXISTING = "EXISTING"
    FIXED = "FIXED"
    REOPENED = "REOPENED"
    CHANGED = "CHANGED"
    SUPPRESSED = "SUPPRESSED"


class RegressionType(str, Enum):
    """Types of security regressions."""

    NEW_VULNERABILITY = "NEW_VULNERABILITY"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
    RISK_ESCALATION = "RISK_ESCALATION"
    AUTHENTICATION_REGRESSION = "AUTHENTICATION_REGRESSION"
    AUTHORIZATION_REGRESSION = "AUTHORIZATION_REGRESSION"
    SECURITY_SCORE_DROP = "SECURITY_SCORE_DROP"


@dataclass
class IntroducingCommit:
    """Commit metadata identifying origin of a vulnerability."""

    commit_sha: str
    author: str
    timestamp: str
    message: str


@dataclass
class SecuritySnapshot:
    """Complete security snapshot of a repository at a point in time."""

    snapshot_id: str
    repository: str
    branch: str
    commit_sha: str
    timestamp: datetime
    scanner_version: str = "1.0.0"
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    security_score: float = 100.0
    attack_paths_count: int = 0


@dataclass
class SecurityRegression:
    """Security regression entry."""

    regression_id: str
    regression_type: RegressionType
    severity: Severity
    description: str
    introducing_commit: IntroducingCommit | None = None


@dataclass
class SnapshotComparison:
    """Result of comparing two SecuritySnapshots."""

    previous_commit: str
    current_commit: str
    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)
    existing_findings: list[Finding] = field(default_factory=list)
    reopened_findings: list[Finding] = field(default_factory=list)
    regressions: list[SecurityRegression] = field(default_factory=list)
    risk_delta: float = 0.0
    security_score_delta: float = 0.0
    trend: str = "stable"
