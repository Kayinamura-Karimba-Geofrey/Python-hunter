"""Governance Engine, Security Approvals, Risk Acceptance, and Policy Inheritance."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity


class ApprovalStatus(str, Enum):
    """Approval request status."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class SecurityApproval:
    """Approval workflow requiring independent reviewer (Four-Eyes Principle)."""

    approval_id: str
    organization_id: str
    requester_user_id: str
    approver_user_id: str | None = None
    action_type: str = ""  # e.g. "POLICY_OVERRIDE", "RISK_ACCEPTANCE", "SUPPRESSION"
    reason: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None

    def approve(self, approver_id: str) -> bool:
        """Approve request enforcing Four-Eyes Principle (requester != approver)."""
        if approver_id == self.requester_user_id:
            # Requester cannot approve their own high-risk exception
            return False
        self.approver_user_id = approver_id
        self.status = ApprovalStatus.APPROVED
        self.resolved_at = datetime.now(timezone.utc)
        return True


@dataclass
class RiskAcceptance:
    """Temporary Risk Acceptance record with automatic expiration."""

    acceptance_id: str
    organization_id: str
    finding_id: str
    accepted_by_user_id: str
    reason: str
    risk_level: Severity
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=90))

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


class GovernanceEngine:
    """Governance Engine managing approvals, risk acceptance expirations, and policy inheritance."""

    def __init__(self) -> None:
        self.approvals: dict[str, SecurityApproval] = {}
        self.risk_acceptances: dict[str, RiskAcceptance] = {}

    def request_approval(self, approval_id: str, org_id: str, requester_id: str, action_type: str, reason: str) -> SecurityApproval:
        appr = SecurityApproval(
            approval_id=approval_id,
            organization_id=org_id,
            requester_user_id=requester_id,
            action_type=action_type,
            reason=reason,
        )
        self.approvals[approval_id] = appr
        return appr

    def approve_request(self, approval_id: str, approver_id: str) -> bool:
        appr = self.approvals.get(approval_id)
        if not appr:
            return False
        return appr.approve(approver_id)

    def record_risk_acceptance(
        self, acceptance_id: str, org_id: str, finding_id: str, user_id: str, reason: str, risk_level: Severity, days: int = 90
    ) -> RiskAcceptance:
        ra = RiskAcceptance(
            acceptance_id=acceptance_id,
            organization_id=org_id,
            finding_id=finding_id,
            accepted_by_user_id=user_id,
            reason=reason,
            risk_level=risk_level,
            expires_at=datetime.now(timezone.utc) + timedelta(days=days),
        )
        self.risk_acceptances[acceptance_id] = ra
        return ra

    def evaluate_active_risk_acceptance(self, finding_id: str) -> RiskAcceptance | None:
        """Returns active risk acceptance if valid and not expired."""
        for ra in self.risk_acceptances.values():
            if ra.finding_id == finding_id and not ra.is_expired:
                return ra
        return None
