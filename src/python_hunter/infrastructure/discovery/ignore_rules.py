"""Ignore Rule Engine with Multi-Tier Precedence."""

import fnmatch
import os


class IgnoreRuleEngine:
    """Ignore rule evaluator applying precedence: Default Rules -> .gitignore -> Config Ignores -> CLI Overrides."""

    DEFAULT_IGNORES: set[str] = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "tests",
        "*.pyc",
        "*.pyo",
        "*.pyd",
    }

    def __init__(
        self,
        gitignore_content: str | None = None,
        config_ignores: list[str] | None = None,
        cli_overrides: list[str] | None = None,
    ) -> None:
        self.gitignore_patterns: list[str] = []
        if gitignore_content:
            self._parse_gitignore(gitignore_content)

        self.config_ignores = config_ignores or []
        self.cli_overrides = cli_overrides or []

    def _parse_gitignore(self, content: str) -> None:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.gitignore_patterns.append(line)

    def is_ignored(self, relative_path: str) -> bool:
        """Check if relative_path should be ignored based on tiered precedence."""
        name = os.path.basename(relative_path)
        parts = relative_path.split(os.sep)

        # Tier 1: Default Ignore Rules
        for part in parts:
            if part in self.DEFAULT_IGNORES:
                return True
        for pattern in self.DEFAULT_IGNORES:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                return True

        # Tier 2: .gitignore Patterns
        for pattern in self.gitignore_patterns:
            clean_pattern = pattern.rstrip("/")
            if fnmatch.fnmatch(name, clean_pattern) or fnmatch.fnmatch(relative_path, clean_pattern):
                return True
            if pattern.endswith("/") and any(p == clean_pattern for p in parts):
                return True

        # Tier 3: Python Hunter Configuration Ignores
        for pattern in self.config_ignores:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                return True

        # Tier 4: CLI Overrides
        for pattern in self.cli_overrides:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                return True

        return False
