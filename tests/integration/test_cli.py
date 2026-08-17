"""Integration tests for CLI execution."""

import unittest
from python_hunter.interfaces.cli.main import run_cli


class TestCLIIntegration(unittest.TestCase):
    """Integration test suite for CLI commands."""

    def test_cli_help(self) -> None:
        """Verify CLI help invocation returns exit code 0."""
        code = run_cli(["--help"])
        self.assertEqual(code, 0)

    def test_cli_version(self) -> None:
        """Verify CLI version command returns exit code 0."""
        code = run_cli(["version"])
        self.assertEqual(code, 0)

    def test_cli_config(self) -> None:
        """Verify CLI config command returns exit code 0."""
        code = run_cli(["config"])
        self.assertEqual(code, 0)

    def test_cli_subcommands_notice(self) -> None:
        """Verify future subcommands display registration notices and exit 0."""
        for cmd in ["scan", "rules", "dependencies", "secrets", "git"]:
            code = run_cli([cmd])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
