"""Unit tests for Baseline Snapshot and SARIF Export Engines."""

import json
import os
import tempfile
import unittest

from python_hunter.domain.baseline.engine import BaselineEngine
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.infrastructure.reporting.sarif_exporter import SARIFExporter


class TestBaselineAndSARIF(unittest.TestCase):
    def test_baseline_creation_and_diff(self) -> None:
        f1 = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.CODE_INJECTION,
            title="Eval Usage",
            description="Eval used",
            file_path="app.py",
            location=Location(line_start=10, line_end=10, column_start=1, column_end=10),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            base_file = os.path.join(tmpdir, "baseline.json")
            base_data = BaselineEngine.create_baseline([f1], base_file)
            self.assertTrue(os.path.exists(base_file))
            self.assertEqual(base_data["count"], 1)

            # Test Diff
            old_scan = {"findings": [base_data["findings"][0]]}
            new_scan = {"findings": []}
            diff = BaselineEngine.diff_scans(old_scan, new_scan)
            self.assertEqual(diff["removed_count"], 1)

    def test_sarif_export(self) -> None:
        f = Finding(
            rule_id="PYH-SEC-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.SECRET,
            title="Secret Exposed",
            description="Exposed API key",
            file_path="secrets.py",
            location=Location(line_start=2, line_end=2, column_start=1, column_end=10),
            remediation="Rotate key immediately.",
        )
        sarif_json = SARIFExporter.export_json([f])
        sarif_data = json.loads(sarif_json)
        self.assertEqual(sarif_data["version"], "2.1.0")
        self.assertEqual(len(sarif_data["runs"][0]["results"]), 1)
        self.assertEqual(sarif_data["runs"][0]["results"][0]["ruleId"], "PYH-SEC-001")


if __name__ == "__main__":
    unittest.main()
