"""Unified ComplianceEngine for Python Hunter."""

from typing import Any, Dict, List, Optional
from python_hunter.domain.compliance.assessment import ComplianceAssessmentEngine
from python_hunter.domain.compliance.evidence import EvidenceEngine
from python_hunter.domain.compliance.models import (
    AssessmentStatus, ComplianceAssessmentModel, ComplianceControlModel,
    ComplianceEvidenceModel, ComplianceExceptionModel, ComplianceFrameworkModel,
    ComplianceGapModel, ControlCategory, ControlState, ExceptionStatus, RiskAcceptanceModel
)
from python_hunter.domain.compliance.registry import ControlRegistry
from python_hunter.domain.compliance.reporting import ComplianceReportingEngine
from python_hunter.domain.findings.finding import Finding


class ComplianceEngine:
    """Enterprise Compliance Engine orchestrating frameworks, controls, evidence, assessment, SLA tracking, and audit reporting."""

    def __init__(self) -> None:
        self.registry = ControlRegistry()
        self.evidence_engine = EvidenceEngine()
        self.assessment_engine = ComplianceAssessmentEngine(self.registry, self.evidence_engine)
        self.reporting_engine = ComplianceReportingEngine()

    def list_frameworks(self) -> List[ComplianceFrameworkModel]:
        return self.registry.list_frameworks()

    def list_controls(self, framework_id: Optional[str] = None) -> List[ComplianceControlModel]:
        return self.registry.list_controls(framework_id)

    def create_assessment(
        self,
        framework_id: str,
        assessor: str = "security-lead",
        organization_id: str = "org-default"
    ) -> ComplianceAssessmentModel:
        return self.assessment_engine.create_assessment(framework_id, assessor, organization_id)

    def evaluate_compliance(
        self,
        assessment_id: str,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """Evaluates findings against compliance controls and records automated evidence."""
        res = self.assessment_engine.evaluate_controls(assessment_id, findings)

        # Collect automated scan evidence for evaluated controls
        scan_summary = {
            "findings_evaluated_count": len(findings),
            "assessment_score": res["overall_score"]
        }
        for ctrl_res in res["evaluated_controls"]:
            self.evidence_engine.collect_automated_scan_evidence(
                control_id=ctrl_res["control_id"],
                scan_result_summary=scan_summary
            )

        return res

    def list_gaps(self, organization_id: str = "org-default") -> List[ComplianceGapModel]:
        return self.assessment_engine.list_gaps(organization_id)

    def request_exception(
        self,
        control_id: str,
        justification: str,
        owner: str,
        organization_id: str = "org-default"
    ) -> ComplianceExceptionModel:
        return self.assessment_engine.request_exception(control_id, justification, owner, organization_id=organization_id)

    def approve_exception(self, exception_id: str, approver: str) -> ComplianceExceptionModel:
        return self.assessment_engine.approve_exception(exception_id, approver)

    def generate_audit_report(self, assessment_id: str, org_name: str = "Default Organization") -> Dict[str, Any]:
        asm = self.assessment_engine._assessments.get(assessment_id)
        if not asm:
            raise KeyError(f"Assessment '{assessment_id}' not found.")
        gaps = self.list_gaps(asm.organization_id)
        return self.reporting_engine.generate_audit_package(asm, gaps, organization_name=org_name)
