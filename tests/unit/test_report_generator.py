"""Unit tests for Executive Security Report Generation."""

import json
import os
import tempfile
import unittest

from python_hunter.application.use_cases.generate_report import GenerateReportUseCase
from python_hunter.interfaces.cli.commands.report import run_report_command
from python_hunter.interfaces.cli.main import run_cli


class TestReportGenerator(unittest.TestCase):
    """Test suite for HTML, Markdown, and JSON executive security report generation."""

    def setUp(self) -> None:
        self.use_case = GenerateReportUseCase()

    def test_generate_html_report(self) -> None:
        result = self.use_case.execute(
            target_path=".",
            report_type="executive",
            format_type="html",
            organization="Acme Cyber Defense",
            title="Q3 Security Assurance Audit",
        )

        self.assertEqual(result["format"], "html")
        self.assertEqual(result["title"], "Q3 Security Assurance Audit")
        self.assertIn("content", result)
        html = result["content"]

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Acme Cyber Defense", html)
        self.assertIn("Q3 Security Assurance Audit", html)
        self.assertIn("Project Risk Score", html)
        self.assertIn("Compliance Grade", html)
        self.assertIn("Top Remediation Priorities", html)
        self.assertIn("Compliance Benchmark Audit", html)

    def test_generate_markdown_report(self) -> None:
        result = self.use_case.execute(
            target_path=".",
            report_type="executive",
            format_type="markdown",
            organization="Global Security Operations",
        )

        self.assertEqual(result["format"], "markdown")
        md = result["content"]
        self.assertTrue(md.startswith("# Executive Security Assurance Report"))
        self.assertIn("Global Security Operations", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Top Remediation Priorities", md)
        self.assertIn("## 3. Compliance Framework Benchmark", md)

    def test_generate_json_report(self) -> None:
        result = self.use_case.execute(
            target_path=".",
            report_type="compliance",
            format_type="json",
            framework_id="OWASP_TOP_10",
        )

        self.assertEqual(result["format"], "json")
        data = json.loads(result["content"])

        self.assertIn("title", data)
        self.assertIn("risk_score", data)
        self.assertIn("compliance_grade", data)
        self.assertIn("compliance_score", data)
        self.assertIn("statistics", data)
        self.assertIn("domain_breakdown", data)
        self.assertIn("compliance_controls", data)
        self.assertIn("top_remediations", data)

    def test_cli_report_command_file_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            # HTML export
            html_out = os.path.join(temp_dir, "exec_report.html")
            code = run_report_command([
                ".",
                "--format", "html",
                "-o", html_out,
                "--organization", "FinTech Core Corp",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(html_out))
            with open(html_out, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("FinTech Core Corp", content)

            # Markdown export
            md_out = os.path.join(temp_dir, "report.md")
            code = run_report_command([
                ".",
                "--format", "markdown",
                "-o", md_out,
            ])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(md_out))

            # JSON export
            json_out = os.path.join(temp_dir, "report.json")
            code = run_report_command([
                ".",
                "--format", "json",
                "-o", json_out,
            ])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(json_out))
            with open(json_out, "r", encoding="utf-8") as f:
                parsed = json.load(f)
            self.assertIn("risk_score", parsed)

    def test_run_cli_report_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = os.path.join(temp_dir, "cli_report.html")
            exit_code = run_cli(["report", ".", "--format", "html", "-o", out_file])
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_file))


if __name__ == "__main__":
    unittest.main()
