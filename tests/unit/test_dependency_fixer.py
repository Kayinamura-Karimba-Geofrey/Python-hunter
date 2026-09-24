"""Unit tests for Automated Dependency Vulnerability Fixes & Version Bumping."""

import json
import os
import tempfile
import unittest

from python_hunter.application.use_cases.fix_dependencies import FixDependenciesUseCase
from python_hunter.domain.dependencies.fixer import DependencyFixEngine
from python_hunter.interfaces.cli.commands.fix import run_fix_command
from python_hunter.interfaces.cli.main import run_cli


class TestDependencyFixEngine(unittest.TestCase):
    """Test suite for manifest updating across requirements.txt, pyproject.toml, and package.json."""

    def test_fix_requirements_txt(self) -> None:
        raw = (
            "# Core dependencies\n"
            "requests>=2.0.0\n"
            "urllib3 # unpinned network\n"
            "click==8.0.0\n"
        )
        updates = {
            "requests": {"package_name": "requests", "old_version": ">=2.0.0", "new_version": "2.31.0", "reason": "Pin requests"},
            "urllib3": {"package_name": "urllib3", "old_version": "unpinned", "new_version": "2.0.7", "reason": "Pin urllib3"},
        }
        fixed, applied = DependencyFixEngine.fix_requirements_txt(raw, updates)

        self.assertEqual(len(applied), 2)
        self.assertIn("requests==2.31.0\n", fixed)
        self.assertIn("urllib3==2.0.7 # unpinned network\n", fixed)
        self.assertIn("click==8.0.0\n", fixed)

    def test_fix_pyproject_toml(self) -> None:
        raw = """[project]
name = "my-service"
version = "0.1.0"
dependencies = [
    "requests>=2.0.0",
    "flask",
    "gunicorn==20.0.0",
]
"""
        updates = {
            "requests": {"package_name": "requests", "old_version": ">=2.0.0", "new_version": "2.31.0", "reason": "Pin requests"},
            "flask": {"package_name": "flask", "old_version": "unpinned", "new_version": "3.0.0", "reason": "Pin flask"},
        }
        fixed, applied = DependencyFixEngine.fix_pyproject_toml(raw, updates)

        self.assertEqual(len(applied), 2)
        self.assertIn('"requests==2.31.0"', fixed)
        self.assertIn('"flask==3.0.0"', fixed)
        self.assertIn('"gunicorn==20.0.0"', fixed)

    def test_fix_package_json(self) -> None:
        raw = json.dumps({
            "name": "frontend",
            "dependencies": {
                "lodash": "^4.17.0",
                "express": "4.18.0"
            }
        }, indent=2)
        updates = {
            "lodash": {"package_name": "lodash", "old_version": "^4.17.0", "new_version": "4.17.21", "reason": "Fix prototype pollution"},
        }
        fixed, applied = DependencyFixEngine.fix_package_json(raw, updates)

        self.assertEqual(len(applied), 1)
        data = json.loads(fixed)
        self.assertEqual(data["dependencies"]["lodash"], "4.17.21")
        self.assertEqual(data["dependencies"]["express"], "4.18.0")


class TestFixDependenciesUseCase(unittest.TestCase):
    """Test application use case for automated dependency fixing."""

    def test_use_case_dry_run_and_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            req_path = os.path.join(temp_dir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("requests>=2.0.0\nflask\n")

            use_case = FixDependenciesUseCase()

            # 1. Test Dry Run (files must remain untouched)
            dry_res = use_case.execute(temp_dir, dry_run=True)
            self.assertTrue(dry_res["dry_run"])
            self.assertGreaterEqual(dry_res["fixes_count"], 2)
            with open(req_path, "r", encoding="utf-8") as f:
                self.assertIn("requests>=2.0.0", f.read())

            # 2. Test Live Fix (files must be modified)
            live_res = use_case.execute(temp_dir, dry_run=False)
            self.assertFalse(live_res["dry_run"])
            self.assertGreaterEqual(live_res["fixes_count"], 2)
            with open(req_path, "r", encoding="utf-8") as f:
                fixed_content = f.read()
            self.assertIn("requests==2.31.0", fixed_content)
            self.assertIn("flask==3.0.0", fixed_content)

    def test_cli_fix_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            req_path = os.path.join(temp_dir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("requests>=2.0.0\n")

            code = run_fix_command([temp_dir, "--dry-run"])
            self.assertEqual(code, 0)

            code = run_cli(["fix", temp_dir])
            self.assertEqual(code, 0)

            with open(req_path, "r", encoding="utf-8") as f:
                self.assertIn("requests==2.31.0", f.read())


if __name__ == "__main__":
    unittest.main()
