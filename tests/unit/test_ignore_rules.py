"""Unit tests for IgnoreRuleEngine."""

import unittest
from python_hunter.infrastructure.discovery.ignore_rules import IgnoreRuleEngine


class TestIgnoreRuleEngine(unittest.TestCase):
    """Test suite for ignore precedence rules."""

    def test_default_ignores(self) -> None:
        """Verify default ignores (.git, __pycache__, .venv)."""
        engine = IgnoreRuleEngine()
        self.assertTrue(engine.is_ignored(".git/config"))
        self.assertTrue(engine.is_ignored("src/__pycache__/core.cpython-312.pyc"))
        self.assertTrue(engine.is_ignored(".venv/lib/python3.12/site-packages/pkg.py"))

    def test_gitignore_parsing(self) -> None:
        """Verify .gitignore pattern matching."""
        gitignore = "build/\n*.log\ncustom_secret.py\n"
        engine = IgnoreRuleEngine(gitignore_content=gitignore)

        self.assertTrue(engine.is_ignored("build/out.py"))
        self.assertTrue(engine.is_ignored("app.log"))
        self.assertTrue(engine.is_ignored("custom_secret.py"))
        self.assertFalse(engine.is_ignored("main.py"))

    def test_cli_overrides(self) -> None:
        """Verify CLI overrides precedence."""
        engine = IgnoreRuleEngine(cli_overrides=["*.tmp"])
        self.assertTrue(engine.is_ignored("temp_file.tmp"))


if __name__ == "__main__":
    unittest.main()
