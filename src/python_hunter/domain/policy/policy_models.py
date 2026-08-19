"""Domain models for Security Policy & Compliance Engine."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding


class PolicyAction(str, Enum):
    """Actions resulting from policy evaluation."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class PolicyException:
    """Expiring exception overriding a security policy violation."""

    exception_id: str
    policy_id: str
    resource: str
    reason: str
    owner: str
    expires_at: datetime


@dataclass
class PolicyRuleCondition:
    """Condition criteria for a policy rule."""

    severity: Severity | None = None
    min_count: int = 1
    min_risk_score: float | None = None
    tags: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


@dataclass
class SecurityPolicy:
    """Security policy definition."""

    policy_id: str
    name: str
    description: str
    action: PolicyAction = PolicyAction.FAIL
    condition: PolicyRuleCondition = field(default_factory=PolicyRuleCondition)


@dataclass
class ComplianceControl:
    """Generic security control mapped to security findings."""

    control_id: str
    title: str
    status: PolicyAction
    evidence_count: int = 0


@dataclass
class GateResult:
    """Summary result of Security Gate evaluation."""

    status: PolicyAction
    policies_evaluated: int
    policies_passed: int
    policies_warned: int
    policies_failed: int
    exit_code: int
    violations: list[str] = field(default_factory=list)
