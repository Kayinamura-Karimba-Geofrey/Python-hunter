"""Unit tests for Unified ScanOrchestrator: SAST, Secrets, SCA, and Malware."""

import json
import os
import tempfile
import unittest

from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.infrastructure.reporting.sarif_exporter import SARIFExporter


class TestUnifiedScanOrchestrator(unittest.TestCase):
    """Test suite verifying end-to-end multi-domain security orchestration."""

    def setUp(self) -> None:
        self.orchestrator = ScanOrchestrator()

    def test_orchestrator_detects_secrets(self) -> None:
        """Verify ScanOrchestrator detects hardcoded credentials in files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = os.path.join(tmp_dir, "config.py")
            with open(config_path, "w", encoding="utf-8") as f:
                f.write('AWS_SECRET_KEY = "AKIA1234567890ABCDEF1234567890ABCDEF"\n')

            result = self.orchestrator.run_scan(tmp_dir)
            self.assertIsNotNone(result)
            rule_ids = [f.rule_id for f in result.findings]
            # Verify secret leak detector found credential
            self.assertTrue(any("SECRET" in rid for rid in rule_ids))

    def test_orchestrator_respects_no_secrets_flag(self) -> None:
        """Verify --no-secrets option disables secret scanning."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = os.path.join(tmp_dir, "config.py")
            with open(config_path, "w", encoding="utf-8") as f:
                f.write('AWS_SECRET_KEY = "AKIA1234567890ABCDEF1234567890ABCDEF"\n')

            result = self.orchestrator.run_scan(tmp_dir, options={"no_secrets": True})
            rule_ids = [f.rule_id for f in result.findings]
            self.assertFalse(any("SECRET" in rid for rid in rule_ids))

    def test_orchestrator_detects_sca_dependencies(self) -> None:
        """Verify ScanOrchestrator detects dependency manifest issues."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            req_path = os.path.join(tmp_dir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("flask>=2.0.0\n")  # Broad version range rule

            result = self.orchestrator.run_scan(tmp_dir)
            rule_ids = [f.rule_id for f in result.findings]
            self.assertTrue(any(rid.startswith("PYH-DEP-") for rid in rule_ids))

    def test_orchestrator_respects_no_dependencies_flag(self) -> None:
        """Verify --no-dependencies option disables SCA scanning."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            req_path = os.path.join(tmp_dir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("flask>=2.0.0\n")

            result = self.orchestrator.run_scan(tmp_dir, options={"no_dependencies": True})
            rule_ids = [f.rule_id for f in result.findings]
            self.assertFalse(any(rid.startswith("PYH-DEP-") for rid in rule_ids))

    def test_unified_sarif_export_contains_multi_domain_findings(self) -> None:
        """Verify SARIF 2.1.0 export contains unified findings from multiple domains."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Add malware artifact
            vscode_dir = os.path.join(tmp_dir, ".vscode")
            os.makedirs(vscode_dir, exist_ok=True)
            with open(os.path.join(vscode_dir, "tasks.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "version": "2.0.0",
                    "tasks": [{"label": "bad", "command": "calc.exe", "runOn": "folderOpen"}]
                }, f)

            # Add dependency
            with open(os.path.join(tmp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
                f.write("requests>=2.0.0\n")

            result = self.orchestrator.run_scan(tmp_dir)
            sarif = SARIFExporter.export(result.findings)

            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 2)
            categories = [
                r["properties"]["category"]
                for r in sarif["runs"][0]["tool"]["driver"]["rules"]
                if "properties" in r and "category" in r["properties"]
            ]
            self.assertIn("MALWARE_RISK", categories)


if __name__ == "__main__":
    unittest.main()
