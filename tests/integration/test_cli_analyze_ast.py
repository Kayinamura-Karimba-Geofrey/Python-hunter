"""Integration tests for CLI analyze-ast command."""

import os
import unittest
from python_hunter.interfaces.cli.main import run_cli

AST_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "ast"))


class TestCLIAnalyzeASTIntegration(unittest.TestCase):
    """Integration test suite for `python-hunter analyze-ast` CLI command."""

    def test_analyze_ast_text_output(self) -> None:
        """Verify analyze-ast command produces exit code 0 for text format."""
        code = run_cli(["analyze-ast", AST_FIXTURES_DIR, "--format", "text"])
        self.assertEqual(code, 0)

    def test_analyze_ast_json_output(self) -> None:
        """Verify analyze-ast command produces exit code 0 for JSON format."""
        code = run_cli(["analyze-ast", AST_FIXTURES_DIR, "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
