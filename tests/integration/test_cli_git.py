"""Integration tests for python-hunter git CLI command."""

import unittest
from python_hunter.interfaces.cli.main import run_cli


class TestCLIGitIntegration(unittest.TestCase):
    """Integration test suite for CLI git subcommand execution."""

    def test_cli_git_current_repo_text(self) -> None:
        exit_code = run_cli(["git", ".", "--commits", "5"])
        self.assertEqual(exit_code, 0)

    def test_cli_git_current_repo_json(self) -> None:
        exit_code = run_cli(["git", ".", "--commits", "5", "--format", "json"])
        self.assertEqual(exit_code, 0)

    def test_cli_git_invalid_repo(self) -> None:
        exit_code = run_cli(["git", "/tmp", "--format", "json"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
