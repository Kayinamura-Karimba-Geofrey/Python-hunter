"""Integration tests for CLI discover command."""

import json
import os
import unittest
from python_hunter.interfaces.cli.main import run_cli

FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "projects"))


class TestCLIDiscoverIntegration(unittest.TestCase):
    """Integration test suite for `python-hunter discover` CLI command."""

    def test_discover_text_output(self) -> None:
        """Verify discover command produces exit code 0 for text format."""
        target = os.path.join(FIXTURES_DIR, "fastapi_project")
        code = run_cli(["discover", target, "--format", "text"])
        self.assertEqual(code, 0)

    def test_discover_json_output(self) -> None:
        """Verify discover command produces exit code 0 for JSON format."""
        target = os.path.join(FIXTURES_DIR, "fastapi_project")
        code = run_cli(["discover", target, "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
