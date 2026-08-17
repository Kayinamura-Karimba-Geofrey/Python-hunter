"""Integration Tests for CLI Vulnerabilities Command."""

import json
from io import StringIO
import sys
import unittest
from unittest.mock import patch

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.vulnerabilities.models import (
    AffectedRange,
    Vulnerability,
)
from python_hunter.infrastructure.vulnerabilities.providers.fake import FakeVulnerabilityProvider
from python_hunter.interfaces.cli.commands.vulnerabilities import run_vulnerabilities_command


class TestCLIVulnerabilitiesCommand(unittest.TestCase):
    """Integration test suite verifying 'python-hunter vulnerabilities' CLI output and options."""

    def test_cli_vulnerabilities_text_format(self) -> None:
        target = "tests/fixtures/vulnerabilities/known_vulnerable"
        
        stdout_capture = StringIO()
        with patch("sys.stdout", stdout_capture):
            exit_code = run_vulnerabilities_command([target, "--offline"])

        self.assertEqual(exit_code, 0)
        output = stdout_capture.getvalue()
        self.assertIn("Python Hunter Vulnerability Intelligence Analysis", output)
        self.assertIn("Dependencies Analyzed", output)

    def test_cli_vulnerabilities_json_format(self) -> None:
        target = "tests/fixtures/vulnerabilities/known_vulnerable"
        
        stdout_capture = StringIO()
        with patch("sys.stdout", stdout_capture):
            exit_code = run_vulnerabilities_command([target, "--offline", "--format", "json"])

        self.assertEqual(exit_code, 0)
        data = json.loads(stdout_capture.getvalue())
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("matches", data)


if __name__ == "__main__":
    unittest.main()
