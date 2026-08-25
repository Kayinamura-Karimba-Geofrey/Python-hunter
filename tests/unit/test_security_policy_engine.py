"""Unit tests for Step 28 Security Policy & Compliance Engine."""

from datetime import datetime, timedelta, timezone

import unittest
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.policy.policy_evaluator import PolicyEngine
from python_hunter.domain.policy.policy_models import PolicyAction, PolicyException


class TestSecurityPolicyEngine(unittest.TestCase):
    """Test suite for policy evaluation, strict profile enforcement, expiring exceptions, and exit code accuracy."""

    def setUp(self) -> None:
        self.policy_engine = PolicyEngine()

    def test_policy_evaluator_pass(self) -> None:
        result = self.policy_engine.evaluate_gate([], risk_score=2.0)
        self.assertEqual(result.status, PolicyAction.PASS)
        self.assertEqual(result.exit_code, 0)

    def test_policy_evaluator_fail_on_critical(self) -> None:
        findings = [
            Finding(
                rule_id="PYHUNTER-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.INJECTION,
                title="Critical Command Injection",
                description="Eval command injection",
                file_path="app.py",
                location=Location(1, 1),
                evidence="eval()",
                remediation="Remove eval",
            )
        ]
        result = self.policy_engine.evaluate_gate(findings, risk_score=9.0)
        self.assertEqual(result.status, PolicyAction.FAIL)
        self.assertEqual(result.exit_code, 1)

    def test_policy_expiring_exception_override(self) -> None:
        findings = [
            Finding(
                rule_id="PYHUNTER-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.INJECTION,
                title="Critical Command Injection",
                description="Eval command injection",
                file_path="app.py",
                location=Location(1, 1),
                evidence="eval()",
                remediation="Remove eval",
            )
        ]
        active_exception = PolicyException(
            exception_id="EX-001",
            policy_id="POL-NO-CRITICAL",
            resource="app.py",
            reason="Approved temporary exception",
            owner="secops@company.com",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        result = self.policy_engine.evaluate_gate(findings, risk_score=2.0, exceptions=[active_exception])
        self.assertEqual(result.status, PolicyAction.PASS)
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
