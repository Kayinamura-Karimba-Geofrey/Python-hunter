"""Unit tests for Step 46 Enterprise Compliance Engine."""

import unittest
from python_hunter.domain.compliance import (
    ComplianceEngine, ControlRegistry, EvidenceEngine, ComplianceAssessmentEngine,
    ComplianceReportingEngine, ControlState, AssessmentStatus, ExceptionStatus, SLAStatus
)
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.common.enums import Severity, Confidence, Category


class TestComplianceEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = ComplianceEngine()
        self.finding = Finding(
            rule_id="PYH-AST-001",
            title="SQL Injection in Auth Service",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.CODE_SECURITY,
            description="Raw string formatting in database query",
            file_path="src/auth.py",
            location=None
        )

    def test_framework_registry(self) -> None:
        frameworks = self.engine.list_frameworks()
        self.assertGreaterEqual(len(frameworks), 7)
        fw_ids = [fw.framework_id for fw in frameworks]
        self.assertIn("OWASP_ASVS_V4", fw_ids)
        self.assertIn("NIST_CSF_V2", fw_ids)
        self.assertIn("SOC_2_TYPE_2", fw_ids)

    def test_control_library(self) -> None:
        controls = self.engine.list_controls()
        self.assertGreaterEqual(len(controls), 5)
        ctrl_ids = [c.control_id for c in controls]
        self.assertIn("CTRL-VULN-001", ctrl_ids)
        self.assertIn("CTRL-SEC-001", ctrl_ids)

    def test_assessment_evaluation(self) -> None:
        asm = self.engine.create_assessment("NIST_CSF_V2", assessor="lead-auditor")
        res = self.engine.evaluate_compliance(asm.assessment_id, [self.finding])
        self.assertEqual(res["assessment_id"], asm.assessment_id)
        self.assertIn("overall_score", res)
        self.assertGreaterEqual(res["failed_controls"], 1)

    def test_four_eyes_review(self) -> None:
        asm = self.engine.create_assessment("SOC_2_TYPE_2", assessor="assessor-1")
        # Self-review should fail
        with self.assertRaises(PermissionError):
            self.engine.assessment_engine.submit_four_eyes_review(asm.assessment_id, reviewer="assessor-1", approved=True)

        # Independent review should succeed
        reviewed = self.engine.assessment_engine.submit_four_eyes_review(asm.assessment_id, reviewer="independent-reviewer-2", approved=True)
        self.assertEqual(reviewed.status, AssessmentStatus.APPROVED)

    def test_evidence_integrity(self) -> None:
        evidence = self.engine.evidence_engine.collect_automated_scan_evidence("CTRL-VULN-001", {"test": "data"})
        self.assertIsNotNone(evidence.content_hash)
        self.assertTrue(self.engine.evidence_engine.verify_integrity(evidence.evidence_id))

    def test_manual_evidence_validation(self) -> None:
        # Unsupported file extension should fail
        with self.assertRaises(ValueError):
            self.engine.evidence_engine.store_manual_evidence("CTRL-MFA-001", "malicious.exe", b"data", uploaded_by="u1")

        # Valid upload
        ev = self.engine.evidence_engine.store_manual_evidence("CTRL-MFA-001", "attestation.pdf", b"PDF bytes", uploaded_by="u1")
        self.assertEqual(ev.source, "Manual Upload (attestation.pdf)")

    def test_exception_lifecycle_and_four_eyes(self) -> None:
        exc = self.engine.request_exception("CTRL-VULN-001", "Legacy system migration", owner="dev-lead")
        # Self approval should fail
        with self.assertRaises(PermissionError):
            self.engine.approve_exception(exc.exception_id, approver="dev-lead")

        # Independent manager approval should succeed
        appr = self.engine.approve_exception(exc.exception_id, approver="secops-manager")
        self.assertEqual(appr.status, ExceptionStatus.APPROVED)

    def test_audit_report_generation(self) -> None:
        asm = self.engine.create_assessment("OWASP_ASVS_V4")
        self.engine.evaluate_compliance(asm.assessment_id, [self.finding])
        report = self.engine.generate_audit_report(asm.assessment_id)
        self.assertIn("report_signature_sha256", report)
        self.assertIsNotNone(report["report_signature_sha256"])


if __name__ == "__main__":
    unittest.main()
