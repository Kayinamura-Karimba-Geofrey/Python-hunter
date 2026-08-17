"""Security test verifying Zero Raw Secret Exposure Guarantee across engine and CLI."""

import io
import json
import sys
import unittest

from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase
from python_hunter.interfaces.cli.commands.secrets import run_secrets_command


class TestSecretLeakPrevention(unittest.TestCase):
    """Security test suite asserting zero raw secrets appear in outputs, JSON, or findings."""

    RAW_SECRET_STRING = "ak_mock_99887766554433221100aabb"

    def test_raw_secret_not_in_findings(self) -> None:
        use_case = AnalyzeSecretsUseCase()
        result = use_case.execute("tests/fixtures/secrets/positive")

        findings = result["findings"]
        self.assertGreaterEqual(len(findings), 1)

        for finding in findings:
            self.assertNotIn(
                self.RAW_SECRET_STRING,
                finding.description,
                "Raw secret leaked into finding description!",
            )
            self.assertNotIn(
                self.RAW_SECRET_STRING,
                finding.evidence,
                "Raw secret leaked into finding evidence!",
            )

    def test_raw_secret_not_in_json_output(self) -> None:
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            run_secrets_command(["tests/fixtures/secrets/positive", "--format", "json"])
        finally:
            sys.stdout = sys.__stdout__

        output_str = captured_output.getvalue()
        self.assertNotIn(
            self.RAW_SECRET_STRING,
            output_str,
            "Raw secret leaked into CLI JSON output!",
        )

        # Verify JSON is valid
        parsed_json = json.loads(output_str)
        self.assertIn("findings", parsed_json)


if __name__ == "__main__":
    unittest.main()
