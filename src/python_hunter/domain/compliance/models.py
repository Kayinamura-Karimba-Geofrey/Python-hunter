"""Domain models for Step 46 Enterprise Compliance Engine."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ControlState(str, Enum):
    """Control evaluation states."""
    NOT_ASSESSED = "NOT_ASSESSED"
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ControlCategory(str, Enum):
    """Control domain categories."""
    ACCESS_CONTROL = "ACCESS_CONTROL"
    ASSET_MANAGEMENT = "ASSET_MANAGEMENT"
    DATA_PROTECTION = "DATA_PROTECTION"
    VULNERABILITY_MANAGEMENT = "VULNERABILITY_MANAGEMENT"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    LOGGING = "LOGGING"
    MONITORING = "MONITORING"
    CHANGE_MANAGEMENT = "CHANGE_MANAGEMENT"
    BUSINESS_CONTINUITY = "BUSINESS_CONTINUITY"
    SUPPLIER_SECURITY = "SUPPLIER_SECURITY"


class AssessmentStatus(str, Enum):
    """Compliance assessment workflow states."""
    DRAFT = "DRAFT"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEW = "REVIEW"
    APPROVED = "APPROVED"
    CLOSED = "CLOSED"


class ExceptionStatus(str, Enum):
    """Compliance exception states."""
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class SLAStatus(str, Enum):
    """Remediation SLA monitoring states."""
    WITHIN_SLA = "WITHIN_SLA"
    APPROACHING_SLA = "APPROACHING_SLA"
    BREACHED_SLA = "BREACHED_SLA"


class ComplianceFrameworkModel:
    """Compliance framework definition."""
    def __init__(
        self,
        framework_id: str,
        name: str,
        version: str,
        description: str,
        effective_date: str = "2024-01-01",
        deprecated_date: Optional[str] = None,
        status: str = "ACTIVE"
    ):
        self.framework_id = framework_id
        self.name = name
        self.version = version
        self.description = description
        self.effective_date = effective_date
        self.deprecated_date = deprecated_date
        self.status = status
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)


class ComplianceControlModel:
    """Security control definition."""
    def __init__(
        self,
        control_id: str,
        framework_id: str,
        title: str,
        description: str,
        category: ControlCategory,
        requirements: List[str],
        mapped_cwes: Optional[List[str]] = None,
        mapped_rule_ids: Optional[List[str]] = None,
        status: ControlState = ControlState.NOT_ASSESSED,
        owner: str = "security-team",
        backup_owner: str = "secops-lead"
    ):
        self.control_id = control_id
        self.framework_id = framework_id
        self.title = title
        self.description = description
        self.category = category
        self.requirements = requirements
        self.mapped_cwes = mapped_cwes or []
        self.mapped_rule_ids = mapped_rule_ids or []
        self.status = status
        self.owner = owner
        self.backup_owner = backup_owner


class ComplianceEvidenceModel:
    """Tamper-evident compliance evidence item."""
    def __init__(
        self,
        evidence_id: str,
        control_id: str,
        source: str,  # Scan, Manual, GitHub, CI/CD
        details: Dict[str, Any],
        organization_id: str = "org-default",
        collected_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        status: str = "VALID",
        collected_by: str = "system"
    ):
        self.evidence_id = evidence_id
        self.control_id = control_id
        self.source = source
        self.details = details
        self.organization_id = organization_id
        self.collected_at = collected_at or datetime.now(timezone.utc)
        self.expires_at = expires_at
        self.status = status
        self.collected_by = collected_by
        # Calculate immutable SHA-256 hash for evidence integrity
        raw_str = f"{evidence_id}:{control_id}:{source}:{str(details)}"
        self.content_hash = hashlib.sha256(raw_str.encode('utf-8')).hexdigest()


class ComplianceGapModel:
    """Identified compliance gap."""
    def __init__(
        self,
        gap_id: str,
        control_id: str,
        current_state: ControlState,
        expected_state: ControlState,
        severity: str,
        remediation_plan: str,
        owner: str,
        organization_id: str = "org-default",
        sla_status: SLAStatus = SLAStatus.WITHIN_SLA
    ):
        self.gap_id = gap_id
        self.control_id = control_id
        self.current_state = current_state
        self.expected_state = expected_state
        self.severity = severity
        self.remediation_plan = remediation_plan
        self.owner = owner
        self.organization_id = organization_id
        self.sla_status = sla_status
        self.created_at = datetime.now(timezone.utc)


class ComplianceExceptionModel:
    """Approved or pending compliance exception."""
    def __init__(
        self,
        exception_id: str,
        control_id: str,
        justification: str,
        owner: str,
        organization_id: str = "org-default",
        approver: Optional[str] = None,
        status: ExceptionStatus = ExceptionStatus.PENDING_APPROVAL,
        expiration_date: Optional[datetime] = None
    ):
        self.exception_id = exception_id
        self.control_id = control_id
        self.justification = justification
        self.owner = owner
        self.organization_id = organization_id
        self.approver = approver
        self.status = status
        self.expiration_date = expiration_date
        self.created_at = datetime.now(timezone.utc)


class RiskAcceptanceModel:
    """Formally documented risk acceptance."""
    def __init__(
        self,
        acceptance_id: str,
        finding_id: str,
        business_justification: str,
        owner: str,
        approver: str,
        organization_id: str = "org-default",
        expiration_date: Optional[datetime] = None
    ):
        self.acceptance_id = acceptance_id
        self.finding_id = finding_id
        self.business_justification = business_justification
        self.owner = owner
        self.approver = approver
        self.organization_id = organization_id
        self.expiration_date = expiration_date
        self.created_at = datetime.now(timezone.utc)


class ComplianceAssessmentModel:
    """Compliance assessment instance."""
    def __init__(
        self,
        assessment_id: str,
        organization_id: str,
        framework_id: str,
        assessor: str,
        reviewer: Optional[str] = None,
        status: AssessmentStatus = AssessmentStatus.DRAFT,
        overall_score: float = 0.0,
        assessment_period: str = "2024-Q1"
    ):
        self.assessment_id = assessment_id
        self.organization_id = organization_id
        self.framework_id = framework_id
        self.assessor = assessor
        self.reviewer = reviewer
        self.status = status
        self.overall_score = overall_score
        self.assessment_period = assessment_period
        self.created_at = datetime.now(timezone.utc)
