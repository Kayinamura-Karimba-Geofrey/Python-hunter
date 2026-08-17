"""Unit tests for Finding Correlator and Attack Path Engine."""

import unittest
from python_hunter.domain.common.enums import (
    Category,
    Confidence,
    ExposureType,
    ReachabilityType,
    Severity,
)
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.findings.finding import Finding


class TestFindingCorrelator(unittest.TestCase):
    def setUp(self) -> None:
        self.correlator = FindingCorrelator()

    def test_deduplicate_identical_findings(self) -> None:
        f1 = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.CODE_INJECTION,
            title="Eval Execution",
            description="Use of eval",
            file_path="app/main.py",
            location=Location(line_start=10, line_end=10, column_start=1, column_end=20),
        )
        f2 = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.CODE_INJECTION,
            title="Eval Execution",
            description="Use of eval duplicate",
            file_path="app/main.py",
            location=Location(line_start=10, line_end=10, column_start=1, column_end=20),
        )
        deduped, _ = self.correlator.correlate([f1, f2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(len(deduped[0].secondary_evidence), 1)

    def test_build_attack_path_for_internet_facing_taint(self) -> None:
        f = Finding(
            rule_id="PYH-TAINT-SQL-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.TAINT,
            title="SQL Injection",
            description="Tainted SQL query",
            file_path="app/views.py",
            location=Location(line_start=25, line_end=25, column_start=5, column_end=30),
            source="request.args.get('id')",
            sink="cursor.execute(query)",
            exposure=ExposureType.INTERNET_FACING,
            reachability=ReachabilityType.REACHABLE,
        )
        deduped, attack_paths = self.correlator.correlate([f])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(len(attack_paths), 1)
        self.assertEqual(attack_paths[0].entry_point, "request.args.get('id')")
        self.assertEqual(attack_paths[0].target_sink, "cursor.execute(query)")


if __name__ == "__main__":
    unittest.main()
