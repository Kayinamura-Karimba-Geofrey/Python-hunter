"""Integration tests for rules and analyze CLI commands."""

import os
import unittest
from python_hunter.interfaces.cli.main import run_cli

RULES_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "security_rules"))


class TestCLIRulesIntegration(unittest.TestCase):
    """Integration test suite for rules list, rules info, and analyze CLI commands."""

    def test_rules_list_command(self) -> None:
        """Verify rules list command exits with status 0."""
        code = run_cli(["rules", "list"])
        self.assertEqual(code, 0)

    def test_rules_info_command(self) -> None:
        """Verify rules info command exits with status 0 for valid rule ID."""
        code = run_cli(["rules", "info", "PYH-AST-001"])
        self.assertEqual(code, 0)

    def test_analyze_text_output(self) -> None:
        """Verify analyze command produces exit code 0 for text format."""
        target = os.path.join(RULES_FIXTURES_DIR, "integration_project")
        code = run_cli(["analyze", target, "--format", "text"])
        self.assertEqual(code, 0)

    def test_analyze_json_output(self) -> None:
        """Verify analyze command produces exit code 0 for JSON format."""
        target = os.path.join(RULES_FIXTURES_DIR, "integration_project")
        code = run_cli(["analyze", target, "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
