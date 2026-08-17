"""Unit tests for Core Domain Models & Scan Lifecycle."""

import unittest
from python_hunter.domain.common.enums import (
    Category,
    Confidence,
    FindingStatus,
    ScanStatus,
    Severity,
)
from python_hunter.domain.common.value_objects import Location, RiskScore
from python_hunter.domain.exceptions.base import ScanError, ValidationError
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.projects.project import Project
from python_hunter.domain.projects.scan import Scan
from python_hunter.domain.projects.target_file import TargetFile
from python_hunter.domain.rules.rule import Rule


class TestDomainModels(unittest.TestCase):
    """Test suite for domain entities and value objects."""

    def test_severity_weights_and_confidence_multipliers(self) -> None:
        """Verify severity weights and confidence multipliers conform to scoring specs."""
        self.assertEqual(Severity.CRITICAL.weight, 10.0)
        self.assertEqual(Severity.HIGH.weight, 7.5)
        self.assertEqual(Severity.MEDIUM.weight, 5.0)
        self.assertEqual(Severity.LOW.weight, 2.5)
        self.assertEqual(Severity.INFO.weight, 0.5)

        self.assertEqual(Confidence.HIGH.multiplier, 1.0)
        self.assertEqual(Confidence.MEDIUM.multiplier, 0.8)
        self.assertEqual(Confidence.LOW.multiplier, 0.5)

    def test_location_validation(self) -> None:
        """Verify Location value object constraints."""
        loc = Location(line_start=10, line_end=15, column_start=5, column_end=20)
        self.assertEqual(loc.line_start, 10)
        self.assertEqual(loc.line_end, 15)

        with self.assertRaises(ValidationError):
            Location(line_start=0, line_end=5)

        with self.assertRaises(ValidationError):
            Location(line_start=20, line_end=10)

    def test_finding_creation_and_fingerprint(self) -> None:
        """Verify Finding entity creation, default status, and SHA-256 fingerprint generation."""
        finding = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.CODE_INJECTION,
            title="Unsafe eval execution",
            description="Use of eval with dynamic inputs",
            file_path="app/main.py",
            location=Location(line_start=42, line_end=42),
        )
        self.assertEqual(finding.status, FindingStatus.OPEN)
        self.assertTrue(len(finding.fingerprint) == 64)  # SHA-256 hex string

        finding.update_status(FindingStatus.FALSE_POSITIVE)
        self.assertEqual(finding.status, FindingStatus.FALSE_POSITIVE)

    def test_scan_lifecycle_valid_transitions(self) -> None:
        """Verify valid scan state transitions: PENDING -> INITIALIZING -> RUNNING -> COMPLETED."""
        project = Project(name="test-project", root_path="/tmp/test")
        scan = Scan(project=project)

        self.assertEqual(scan.status, ScanStatus.PENDING)
        self.assertIsNone(scan.started_at)
        self.assertIsNone(scan.completed_at)

        scan.transition_to(ScanStatus.INITIALIZING)
        self.assertEqual(scan.status, ScanStatus.INITIALIZING)
        self.assertIsNotNone(scan.started_at)

        scan.transition_to(ScanStatus.RUNNING)
        self.assertEqual(scan.status, ScanStatus.RUNNING)

        scan.transition_to(ScanStatus.COMPLETED)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertIsNotNone(scan.completed_at)

    def test_scan_lifecycle_invalid_transitions(self) -> None:
        """Verify invalid scan state transitions raise ScanError."""
        project = Project(name="test-project", root_path="/tmp/test")
        scan = Scan(project=project)

        # Cannot jump directly from PENDING to RUNNING
        with self.assertRaises(ScanError):
            scan.transition_to(ScanStatus.RUNNING)

        scan.transition_to(ScanStatus.INITIALIZING)
        scan.transition_to(ScanStatus.RUNNING)
        scan.transition_to(ScanStatus.COMPLETED)

        # Terminal state cannot transition to RUNNING
        with self.assertRaises(ScanError):
            scan.transition_to(ScanStatus.RUNNING)

    def test_risk_score_calculation(self) -> None:
        """Verify scan composite risk score calculation."""
        project = Project(name="test-project", root_path="/tmp/test")
        scan = Scan(project=project)

        # Empty scan has 0.0 risk score
        self.assertEqual(scan.calculate_risk_score().score, 0.0)

        # Add critical finding
        finding = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.CODE_INJECTION,
            title="Unsafe eval",
            description="Dynamic eval call",
            file_path="main.py",
            location=Location(line_start=5, line_end=5),
        )
        scan.findings.append(finding)
        score = scan.calculate_risk_score()
        self.assertGreater(score.score, 0.0)
        self.assertIsInstance(score.grade, Severity)


if __name__ == "__main__":
    unittest.main()
