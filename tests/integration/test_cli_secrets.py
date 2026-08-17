"""Integration test for python-hunter secrets CLI command."""

import io
import json
import sys
import unittest

from python_hunter.interfaces.cli.commands.secrets import run_secrets_command


class TestCLISecretsIntegration(unittest.TestCase):
    """Integration test suite verifying python-hunter secrets command execution."""

    def test_secrets_command_text(self) -> None:
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            exit_code = run_secrets_command(["tests/fixtures/secrets/positive", "--format", "text"])
        finally:
            sys.stdout = sys.__stdout__

        self.assertEqual(exit_code, 0)
        output = captured_output.getvalue()
        self.assertIn("Python Hunter Secret Detection", output)
        self.assertIn("Total Findings:", output)

    def test_secrets_command_json(self) -> None:
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            exit_code = run_secrets_command(["tests/fixtures/secrets/positive", "--format", "json"])
        finally:
            sys.stdout = sys.__stdout__

        self.assertEqual(exit_code, 0)
        output = captured_output.getvalue()
        data = json.loads(output)
        self.assertIn("files_scanned", data)
        self.assertIn("total_findings", data)


if __name__ == "__main__":
    unittest.main()
