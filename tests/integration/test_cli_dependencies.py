"""Integration tests for CLI dependencies command."""

import unittest
from python_hunter.interfaces.cli.commands.dependencies import run_dependencies_command


class TestCLIDependenciesIntegration(unittest.TestCase):
    """Integration test suite for python-hunter dependencies command."""

    def test_dependencies_text_format(self) -> None:
        """Verify text output format of dependencies command."""
        code = run_dependencies_command(["tests/fixtures/dependencies/requirements", "--format", "text"])
        self.assertEqual(code, 0)

    def test_dependencies_tree_format(self) -> None:
        """Verify ascii tree output format of dependencies command."""
        code = run_dependencies_command(["tests/fixtures/dependencies/poetry", "--tree", "--format", "text"])
        self.assertEqual(code, 0)

    def test_dependencies_json_format(self) -> None:
        """Verify JSON output format of dependencies command."""
        code = run_dependencies_command(["tests/fixtures/dependencies/requirements", "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
