"""Unit tests for Step 39 — Security Testing & Safe Exploitability Verification."""

import unittest
from datetime import datetime, timezone, timedelta

from python_hunter.domain.common.enums import (
    TestSafetyLevel,
    VerificationConfidence,
    VerificationMode,
    VerificationStatus,
)
from python_hunter.domain.verification.models import (
    SecurityTest,
    VerificationAuthorization,
    VerificationResult,
)
from python_hunter.domain.verification.payloads import SafePayloadRegistry
from python_hunter.domain.verification.planner import SafetyValidator, VerificationPlanner
from python_hunter.domain.verification.engine import (
    PassiveVerifier,
    VerificationEngine,
    VerificationSandbox,
)
from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestSecurityVerificationEngine(unittest.TestCase):
    """Verifies passive evidence upgrades, safety authorization validator, active sandbox execution, and refusal controls."""

    def setUp(self) -> None:
        self.engine = VerificationEngine()
        self.app_service = SecurityApplicationService()

    def test_passive_verification_evidence_upgrade(self) -> None:
        """Verifies static evidence upgrades confidence without target execution."""
        finding = {
            "id": "f-sqli-01",
            "rule_id": "PYH-AST-001",
            "title": "Unsafe SQL Query Construction",
            "file_path": "src/db.py",
            "reachability": "REACHABLE",
            "source": "request.args.get('id')",
            "sink": "db.execute()",
            "confidence": "HIGH",
        }

        res = self.engine.verify_finding(finding, mode=VerificationMode.PASSIVE)
        self.assertEqual(res.verification_status, VerificationStatus.LIKELY_EXPLOITABLE)
        self.assertEqual(res.confidence, VerificationConfidence.HIGH)
        self.assertEqual(res.safety_level, TestSafetyLevel.PASSIVE_ONLY)
        self.assertIn("Passive Verification Confirmed", res.evidence)

    def test_safety_validator_denylist_blocking(self) -> None:
        """Verifies SafetyValidator blocks production IPs, cloud metadata, and external targets."""
        # Cloud Metadata IMDS
        allowed, reason = SafetyValidator.is_target_allowed("http://169.254.169.254/latest/meta-data")
        self.assertFalse(allowed)
        self.assertIn("denylist", reason.lower())

        # Production Domain
        allowed, reason = SafetyValidator.is_target_allowed("https://api.production.company.com")
        self.assertFalse(allowed)

        # Authorized Localhost
        allowed, reason = SafetyValidator.is_target_allowed("http://127.0.0.1:8080")
        self.assertTrue(allowed)

    def test_active_verification_refusal_without_authorization(self) -> None:
        """Verifies active verification is strictly REFUSED without explicit valid authorization."""
        finding = {
            "id": "f-cmdi-01",
            "rule_id": "PYH-AST-004",
            "title": "Unsafe os.system command execution",
            "file_path": "src/utils.py",
        }

        res = self.engine.verify_finding(
            finding, mode=VerificationMode.ACTIVE, authorization=None, target="http://127.0.0.1:8080"
        )
        self.assertEqual(res.verification_status, VerificationStatus.NOT_VERIFIED)
        self.assertEqual(res.test_method, "PLANNER_REFUSAL")
        self.assertIn("requires explicit --authorized-target", res.evidence)

    def test_active_verification_dry_run(self) -> None:
        """Verifies dry-run mode previews test plan without execution."""
        finding = {
            "id": "f-cmdi-01",
            "rule_id": "PYH-AST-004",
            "title": "Unsafe os.system command execution",
            "file_path": "src/utils.py",
        }
        auth = VerificationAuthorization.create_temporary_authorization("http://127.0.0.1:8080")

        res = self.engine.verify_finding(
            finding, mode=VerificationMode.ACTIVE, authorization=auth, target="http://127.0.0.1:8080", dry_run=True
        )
        self.assertEqual(res.verification_status, VerificationStatus.NOT_TESTED)
        self.assertEqual(res.test_method, "DRY_RUN")
        self.assertIn("DRY RUN", res.evidence)

    def test_application_service_verification_flow(self) -> None:
        """Verifies SecurityApplicationService integration for passive and active verification."""
        # Passive Service Verification
        res_p = self.app_service.verify_finding("f-sqli-01", active=False)
        self.assertIn(res_p["verification_status"], ("LIKELY_EXPLOITABLE", "VERIFIED", "NOT_VERIFIED"))

        # Active Service Verification with Target Authorization
        self.app_service.authorize_verification_target("http://127.0.0.1:8080")
        res_a = self.app_service.verify_finding("f-sqli-01", active=True, target="http://127.0.0.1:8080", dry_run=True)
        self.assertEqual(res_a["test_method"], "DRY_RUN")

    def test_payload_redaction(self) -> None:
        """Verifies secret redactor strips sensitive keys from payloads."""
        raw_log = "Sending request with api_key='sk_live_secret12345' to target"
        redacted = SafePayloadRegistry.redact_payload(raw_log)
        self.assertNotIn("sk_live_secret12345", redacted)
        self.assertIn("[REDACTED_VERIFICATION_PAYLOAD]", redacted)


if __name__ == "__main__":
    unittest.main()
