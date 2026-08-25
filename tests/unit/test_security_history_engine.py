"""Unit tests for Step 29 Historical Security Intelligence Engine."""

from datetime import datetime, timezone
import unittest
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.history.history_engine import SecurityHistoryStore, SnapshotComparator
from python_hunter.domain.history.history_models import SecuritySnapshot


class TestSecurityHistoryEngine(unittest.TestCase):
    """Test suite for snapshot storage, stable fingerprinting, lifecycle classification (NEW/FIXED/EXISTING), and risk deltas."""

    def setUp(self) -> None:
        self.store = SecurityHistoryStore()
        self.comparator = SnapshotComparator()

    def test_snapshot_comparison_clean_and_regressed(self) -> None:
        f1 = Finding(
            rule_id="PYHUNTER-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.INJECTION,
            title="SQL Injection",
            description="Unsanitized query",
            file_path="app.py",
            location=Location(10, 10),
            evidence="db.execute(query)",
            remediation="Use params",
        )

        snap1 = SecuritySnapshot(
            snapshot_id="s1",
            repository="repo",
            branch="main",
            commit_sha="c111111",
            timestamp=datetime.now(timezone.utc),
            findings=[],
            risk_score=0.0,
            security_score=100.0,
        )

        snap2 = SecuritySnapshot(
            snapshot_id="s2",
            repository="repo",
            branch="main",
            commit_sha="c222222",
            timestamp=datetime.now(timezone.utc),
            findings=[f1],
            risk_score=7.5,
            security_score=75.0,
        )


        comp = self.comparator.compare(snap1, snap2)
        self.assertEqual(len(comp.new_findings), 1)
        self.assertEqual(len(comp.regressions), 1)
        self.assertEqual(comp.trend, "degrading")
        self.assertEqual(comp.security_score_delta, -25.0)

    def test_fingerprint_stability_across_line_movement(self) -> None:
        f_line10 = Finding(
            rule_id="PYHUNTER-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.INJECTION,
            title="SQL Injection",
            description="Unsanitized query",
            file_path="app.py",
            location=Location(10, 10),
            evidence="db.execute(query)",
            remediation="Use params",
        )
        f_line150 = Finding(
            rule_id="PYHUNTER-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.INJECTION,
            title="SQL Injection",
            description="Unsanitized query",
            file_path="app.py",
            location=Location(150, 150),
            evidence="db.execute(query)",
            remediation="Use params",
        )

        fp1 = self.comparator.compute_fingerprint(f_line10)
        fp2 = self.comparator.compute_fingerprint(f_line150)
        self.assertEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()
