"""Unit tests for Risk Scoring and Security Policy Engines."""

import unittest
from python_hunter.domain.common.enums import (
    Category,
    Confidence,
    ExposureType,
    FindingLifecycleState,
    ReachabilityType,
    Severity,
)
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.policy.engine import SecurityPolicy, SecurityPolicyEngine


class TestRiskAndPolicyEngine(unittest.TestCase):
    def test_risk_score_calculation(self) -> None:
        risk_engine = RiskEngine()
        f = Finding(
            rule_id="PYH-TAINT-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.TAINT,
            title="Remote Code Execution",
            description="Tainted eval execution",
            file_path="app/auth/routes.py",
            location=Location(line_start=15, line_end=15, column_start=1, column_end=10),
            exposure=ExposureType.INTERNET_FACING,
            reachability=ReachabilityType.REACHABLE,
            source="req.param",
            sink="eval()",
        )
        exp = risk_engine.evaluate_finding_risk(f)
        self.assertGreaterEqual(exp.final_score, 80.0)

    def test_policy_evaluation_violations(self) -> None:
        policy = SecurityPolicy(fail_on=Severity.HIGH, max_critical=0)
        policy_engine = SecurityPolicyEngine(policy=policy)

        f = Finding(
            rule_id="PYH-SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SECRET,
            title="AWS Access Key Exposed",
            description="Hardcoded AWS key",
            file_path="config.py",
            location=Location(line_start=5, line_end=5, column_start=1, column_end=10),
        )

        passed, violations = policy_engine.evaluate([f], project_risk_score=85.0)
        self.assertFalse(passed)
        self.assertGreaterEqual(len(violations), 1)

    def test_policy_suppression(self) -> None:
        policy = SecurityPolicy(
            suppressions=[
                {"rule_id": "PYH-SEC-001", "file": "test_config.py", "reason": "Test fixture key"}
            ]
        )
        policy_engine = SecurityPolicyEngine(policy=policy)

        f = Finding(
            rule_id="PYH-SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SECRET,
            title="AWS Key",
            description="Test key",
            file_path="test_config.py",
            location=Location(line_start=5, line_end=5, column_start=1, column_end=10),
        )

        passed, _ = policy_engine.evaluate([f], project_risk_score=10.0)
        self.assertEqual(f.lifecycle_state, FindingLifecycleState.SUPPRESSED)
        self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
