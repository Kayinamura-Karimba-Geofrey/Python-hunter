"""Unit tests for Security Reporters (Terminal, JSON, SARIF, Markdown, HTML, CSV) & Redaction."""

import json
import unittest

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.correlation.models import AttackPath, AttackPathType, SecurityPosture
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.reporting.dashboard_services import SecurityReportService
from python_hunter.domain.reporting.models import AnalysisMetadata, ScanMetadata
from python_hunter.infrastructure.reporting.base import ReporterRegistry
from python_hunter.infrastructure.reporting.csv_reporter import CsvReporter
from python_hunter.infrastructure.reporting.html_reporter import HtmlReporter
from python_hunter.infrastructure.reporting.json_reporter import JsonReporter
from python_hunter.infrastructure.reporting.markdown_reporter import MarkdownReporter
from python_hunter.infrastructure.reporting.redaction import SecretRedactor
from python_hunter.infrastructure.reporting.sarif_exporter import SarifReporter
from python_hunter.infrastructure.reporting.terminal import TerminalReporter


class TestSecurityReporters(unittest.TestCase):
    """Test suite verifying all reporting formatters and secret redaction."""

    def setUp(self) -> None:
        self.secret_finding = Finding(
            rule_id="PYH-SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SECRET,
            title="Exposed AWS Secret Key",
            description="Hardcoded AWS secret key found in source code",
            file_path="src/config.py",
            location=None,
            evidence="aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            remediation="Move AWS secret to environment variables or secret manager",
            risk_score=95.0,
        )

        self.taint_finding = Finding(
            rule_id="PYH-TAINT-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.TAINT_ANALYSIS,
            title="Untrusted Data in Command Execution",
            description="Untrusted user input flows into subprocess.run shell execution",
            file_path="src/utils.py",
            location=None,
            evidence="subprocess.run(cmd, shell=True)",
            source="request.args.get('cmd')",
            sink="subprocess.run",
            remediation="Use argument list without shell=True",
            risk_score=85.0,
        )

        self.findings = [self.secret_finding, self.taint_finding]
        self.attack_path = AttackPath(
            id="ap-1",
            title="Command Injection via HTTP Input",
            attack_type=AttackPathType.COMMAND_INJECTION,
            entry_point="request.args.get('cmd')",
            target_sink="subprocess.run",
            risk_score=90.0,
        )
        self.posture = SecurityPosture(project_risk_score=88.0, policy_passed=False, policy_violations=["Critical finding PYH-SEC-001"])

        self.scan_meta = ScanMetadata(scan_id="scan-123", project_name="test-project", project_path=".")
        self.analysis_meta = AnalysisMetadata(python_version="3.11", operating_system="Linux")

        self.report = SecurityReportService.create_report(
            findings=self.findings,
            attack_paths=[self.attack_path],
            posture=self.posture,
            scan_metadata=self.scan_meta,
            analysis_metadata=self.analysis_meta,
        )

    def test_secret_redaction(self) -> None:
        redacted = SecretRedactor.redact_finding(self.secret_finding)
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", redacted.evidence)
        self.assertIn("[REDACTED_AWS_SECRET]", redacted.evidence)

    def test_terminal_reporter(self) -> None:
        reporter = ReporterRegistry.get("terminal")
        out = reporter.render(self.report)
        self.assertIn("Python Hunter Security Report", out)
        self.assertIn("88.0/100", out)
        self.assertIn("FAILED", out)
        self.assertIn("PYH-SEC-001", out)

    def test_json_reporter(self) -> None:
        reporter = ReporterRegistry.get("json")
        out = reporter.render(self.report)
        doc = json.loads(out)
        self.assertEqual(doc["schema_version"], "1.0")
        self.assertEqual(doc["scan_metadata"]["project_name"], "test-project")
        self.assertEqual(doc["risk_metrics"]["project_risk_score"], 88.0)
        self.assertEqual(len(doc["findings"]), 2)

    def test_sarif_reporter(self) -> None:
        reporter = ReporterRegistry.get("sarif")
        out = reporter.render(self.report)
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "Python Hunter")
        self.assertEqual(len(doc["runs"][0]["results"]), 2)

    def test_markdown_reporter(self) -> None:
        reporter = ReporterRegistry.get("markdown")
        out = reporter.render(self.report)
        self.assertIn("# Security Intelligence Report", out)
        self.assertIn("88.0/100", out)
        self.assertIn("Command Injection via HTTP Input", out)
        self.assertIn("PYH-SEC-001", out)

    def test_html_reporter(self) -> None:
        reporter = ReporterRegistry.get("html")
        out = reporter.render(self.report)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("Python Hunter Security Intelligence", out)
        self.assertIn("GATE FAILED", out)
        self.assertIn("PYH-SEC-001", out)

    def test_csv_reporter(self) -> None:
        reporter = ReporterRegistry.get("csv")
        out = reporter.render(self.report)
        lines = out.strip().split("\n")
        self.assertTrue(lines[0].startswith("finding_id,rule_id"))
        self.assertIn("PYH-SEC-001", lines[1])


if __name__ == "__main__":
    unittest.main()
