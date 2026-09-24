"""Unit tests for Interactive Terminal TUI Dashboard."""

import io
import unittest
from unittest.mock import patch

from python_hunter.application.orchestrator.scan_context import ScanContext, ScanResult
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.graph.models import WholeProjectRisk
from python_hunter.interfaces.cli.commands.tui import run_tui_command
from python_hunter.interfaces.cli.main import run_cli
from python_hunter.presentation.tui import SecurityTUI


class TestSecurityTUI(unittest.TestCase):
    """Test suite for SecurityTUI component and snapshot rendering."""

    def setUp(self) -> None:
        self.finding1 = Finding(
            rule_id="PYH-MAL-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.MALWARE_RISK,
            title="TasksJacker VS Code Hijacking",
            description="Malicious folderOpen auto task execution",
            file_path=".vscode/tasks.json",
            location=Location(1, 1, 0, 10),
            evidence="folderOpen: bash payload.sh",
            remediation="Remove folderOpen task",
        )
        self.finding2 = Finding(
            rule_id="PYH-SECRET-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.SECRET_LEAK,
            title="Exposed AWS API Key",
            description="High-entropy token detected",
            file_path="config.py",
            location=Location(10, 10, 0, 20),
            evidence="AKIAIOSFODNN7EXAMPLE",
            remediation="Rotate credentials immediately",
        )
        self.scan_res = ScanResult(
            context=ScanContext(scan_id="test-scan"),
            findings=[self.finding1, self.finding2],
            project_risk=WholeProjectRisk(
                overall_score=85.0,
                exposure_score=0.0,
                vulnerability_score=0.0,
                dependency_score=0.0,
                malware_score=0.0,
                control_coverage_score=0.0,
                critical_attack_paths_count=0,
            ),
            exit_code=1,
        )

    def test_tui_tabs_filtering(self) -> None:
        tui = SecurityTUI(target_path=".", scan_result=self.scan_res)

        # Tab 0: ALL
        all_f = tui.get_tab_findings(0)
        self.assertEqual(len(all_f), 2)

        # Tab 1: MALWARE
        malware_f = tui.get_tab_findings(1)
        self.assertEqual(len(malware_f), 1)
        self.assertEqual(malware_f[0].rule_id, "PYH-MAL-001")

        # Tab 2: SECRETS
        secrets_f = tui.get_tab_findings(2)
        self.assertEqual(len(secrets_f), 1)
        self.assertEqual(secrets_f[0].rule_id, "PYH-SECRET-001")

        # Tab 3: SUPPLY_CHAIN
        supply_f = tui.get_tab_findings(3)
        self.assertEqual(len(supply_f), 0)

    def test_tui_render_snapshot(self) -> None:
        tui = SecurityTUI(target_path="test-repo", scan_result=self.scan_res)
        snapshot = tui.render_snapshot()

        self.assertIn("PYTHON HUNTER TUI DASHBOARD", snapshot)
        self.assertIn("Target: test-repo", snapshot)
        self.assertIn("Risk: 85.0/100", snapshot)
        self.assertIn("Policy Gate: FAILED", snapshot)
        self.assertIn("PYH-MAL-001", snapshot)
        self.assertIn("PYH-SECRET-001", snapshot)

    def test_cli_tui_command_snapshot(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = run_tui_command([".", "--snapshot"])
            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("PYTHON HUNTER TUI DASHBOARD", output)

    def test_run_cli_tui_subcommand(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = run_cli(["tui", ".", "--snapshot"])
            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("PYTHON HUNTER TUI DASHBOARD", output)


if __name__ == "__main__":
    unittest.main()
