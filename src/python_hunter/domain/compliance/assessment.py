"""Compliance Assessment, SLA Engine, Four-Eyes Review & Gap Analysis."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from python_hunter.domain.compliance.evidence import EvidenceEngine
from python_hunter.domain.compliance.models import (
    AssessmentStatus, ComplianceAssessmentModel, ComplianceControlModel,
    ComplianceExceptionModel, ComplianceGapModel, ControlState, ExceptionStatus,
    RiskAcceptanceModel, SLAStatus
)
from python_hunter.domain.compliance.registry import ControlRegistry
from python_hunter.domain.findings.finding import Finding


class ComplianceAssessmentEngine:
    """Evaluates security controls, calculates transparent scores, tracks SLA breaches, and manages exceptions."""

    # Remediation SLA thresholds (Days)
    SLA_THRESHOLDS = {
        "CRITICAL": 7,
        "HIGH": 30,
        "MEDIUM": 60,
        "LOW": 90
    }

    def __init__(self, registry: Optional[ControlRegistry] = None, evidence_engine: Optional[EvidenceEngine] = None) -> None:
        self.registry = registry or ControlRegistry()
        self.evidence_engine = evidence_engine or EvidenceEngine()
        self._assessments: Dict[str, ComplianceAssessmentModel] = {}
        self._gaps: Dict[str, ComplianceGapModel] = {}
        self._exceptions: Dict[str, ComplianceExceptionModel] = {}
        self._risk_acceptances: Dict[str, RiskAcceptanceModel] = {}

    def create_assessment(
        self,
        framework_id: str,
        assessor: str,
        organization_id: str = "org-default",
        assessment_period: str = "2024-Q1"
    ) -> ComplianceAssessmentModel:
        ass_id = f"asm-{uuid.uuid4().hex[:8]}"
        assessment = ComplianceAssessmentModel(
            assessment_id=ass_id,
            organization_id=organization_id,
            framework_id=framework_id,
            assessor=assessor,
            status=AssessmentStatus.DRAFT,
            assessment_period=assessment_period
        )
        self._assessments[ass_id] = assessment
        return assessment

    def submit_four_eyes_review(
        self,
        assessment_id: str,
        reviewer: str,
        approved: bool,
        notes: str = ""
    ) -> ComplianceAssessmentModel:
        """Enforces independent review where reviewer cannot be the original assessor."""
        asm = self._assessments.get(assessment_id)
        if not asm:
            raise KeyError(f"Assessment '{assessment_id}' not found.")

        if asm.assessor == reviewer:
            raise PermissionError("Four-Eyes Review Failure: Independent reviewer cannot be the original assessor.")

        asm.reviewer = reviewer
        if approved:
            asm.status = AssessmentStatus.APPROVED
        else:
            asm.status = AssessmentStatus.REVIEW

        return asm

    def evaluate_controls(
        self,
        assessment_id: str,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """Evaluates framework controls against findings, evidence, and active exceptions."""
        asm = self._assessments.get(assessment_id)
        if not asm:
            raise KeyError(f"Assessment '{assessment_id}' not found.")

        controls = self.registry.list_controls(asm.framework_id)
        if not controls:
            # Fallback to all library controls
            controls = self.registry.list_controls()

        compliant_count = 0
        failed_count = 0
        partial_count = 0

        evaluated_controls = []

        for ctrl in controls:
            # Check for active approved exception
            active_exception = self._get_active_exception(ctrl.control_id, asm.organization_id)
            if active_exception:
                state = ControlState.NOT_APPLICABLE
                evaluated_controls.append({
                    "control_id": ctrl.control_id,
                    "title": ctrl.title,
                    "state": state,
                    "reason": f"Active exception approved by {active_exception.approver}"
                })
                compliant_count += 1
                continue

            # Check matching findings by rule_id or cwe
            matching_findings = [
                f for f in findings
                if f.rule_id in ctrl.mapped_rule_ids
            ]

            if not matching_findings:
                state = ControlState.COMPLIANT
                compliant_count += 1
            else:
                crit_high = [f for f in matching_findings if hasattr(f, 'severity') and f.severity.value in ["CRITICAL", "HIGH"]]
                if crit_high:
                    state = ControlState.NON_COMPLIANT
                    failed_count += 1
                    # Generate Gap
                    self._create_gap(ctrl, matching_findings[0], asm.organization_id)
                else:
                    state = ControlState.PARTIALLY_COMPLIANT
                    partial_count += 1

            ctrl.status = state
            evaluated_controls.append({
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "state": state,
                "findings_count": len(matching_findings)
            })

        total = len(controls)
        overall_score = round((compliant_count / total) * 100, 1) if total > 0 else 100.0
        asm.overall_score = overall_score
        asm.status = AssessmentStatus.IN_PROGRESS

        return {
            "assessment_id": assessment_id,
            "overall_score": overall_score,
            "compliant_controls": compliant_count,
            "failed_controls": failed_count,
            "partially_compliant_controls": partial_count,
            "total_controls": total,
            "evaluated_controls": evaluated_controls
        }

    def _create_gap(self, ctrl: ComplianceControlModel, finding: Finding, org_id: str) -> None:
        gap_id = f"gap-{ctrl.control_id}-{uuid.uuid4().hex[:4]}"
        sev = finding.severity.value if hasattr(finding, 'severity') and hasattr(finding.severity, 'value') else "HIGH"

        # Calculate SLA breach status
        created_at = datetime.now(timezone.utc)
        sla_days = self.SLA_THRESHOLDS.get(sev.upper(), 30)
        due_date = created_at + timedelta(days=sla_days)

        sla_status = SLAStatus.WITHIN_SLA
        if datetime.now(timezone.utc) > due_date:
            sla_status = SLAStatus.BREACHED_SLA

        gap = ComplianceGapModel(
            gap_id=gap_id,
            control_id=ctrl.control_id,
            current_state=ControlState.NON_COMPLIANT,
            expected_state=ControlState.COMPLIANT,
            severity=sev,
            remediation_plan=f"Remediate finding {finding.rule_id} ({finding.title}) to satisfy control {ctrl.title}.",
            owner=ctrl.owner,
            organization_id=org_id,
            sla_status=sla_status
        )
        self._gaps[gap_id] = gap

    def request_exception(
        self,
        control_id: str,
        justification: str,
        owner: str,
        expiration_days: int = 30,
        organization_id: str = "org-default"
    ) -> ComplianceExceptionModel:
        exp_id = f"exc-{uuid.uuid4().hex[:8]}"
        exception = ComplianceExceptionModel(
            exception_id=exp_id,
            control_id=control_id,
            justification=justification,
            owner=owner,
            organization_id=organization_id,
            expiration_date=datetime.now(timezone.utc) + timedelta(days=expiration_days),
            status=ExceptionStatus.PENDING_APPROVAL
        )
        self._exceptions[exp_id] = exception
        return exception

    def approve_exception(self, exception_id: str, approver: str) -> ComplianceExceptionModel:
        exc = self._exceptions.get(exception_id)
        if not exc:
            raise KeyError(f"Exception '{exception_id}' not found.")
        if exc.owner == approver:
            raise PermissionError("Approval Failure: Exception requestor cannot self-approve exception.")

        exc.approver = approver
        exc.status = ExceptionStatus.APPROVED
        return exc

    def _get_active_exception(self, control_id: str, org_id: str) -> Optional[ComplianceExceptionModel]:
        now = datetime.now(timezone.utc)
        for exc in self._exceptions.values():
            if exc.control_id == control_id and exc.organization_id == org_id:
                if exc.status == ExceptionStatus.APPROVED:
                    if exc.expiration_date and exc.expiration_date < now:
                        exc.status = ExceptionStatus.EXPIRED
                        continue
                    return exc
        return None

    def list_gaps(self, org_id: str = "org-default") -> List[ComplianceGapModel]:
        return [g for g in self._gaps.values() if g.organization_id == org_id]
