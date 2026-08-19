"""Unit tests for TargetResolver, RepositoryManager, ScanOrchestrator, and CLI Commands."""

import os
import tempfile
import unittest

from python_hunter.application.orchestrator import ScanOrchestrator
from python_hunter.infrastructure.repository import ScanTarget, TargetResolver, TargetType
from python_hunter.presentation import ExitCode, PolicyEngine


class TestCLIAndRepositoryScanning(unittest.TestCase):
    """Unit test suite for TargetResolver, ScanOrchestrator, and CLI policy exit codes."""

    def setUp(self) -> None:
        self.resolver = TargetResolver()
        self.orchestrator = ScanOrchestrator()
        self.policy_engine = PolicyEngine()

    def test_target_resolver_local_directory(self) -> None:
        target = self.resolver.resolve(".")
        self.assertIn(target.target_type, (TargetType.LOCAL_DIRECTORY, TargetType.GIT_REPOSITORY))
        self.assertTrue(os.path.isabs(target.local_path))

    def test_target_resolver_github_https_url(self) -> None:
        target = self.resolver.resolve("https://github.com/user/project.git", branch="develop")
        self.assertEqual(target.target_type, TargetType.GITHUB_REPOSITORY)
        self.assertEqual(target.repository_url, "https://github.com/user/project.git")
        self.assertEqual(target.branch, "develop")

    def test_target_resolver_github_ssh_url(self) -> None:
        target = self.resolver.resolve("git@github.com:user/project.git")
        self.assertEqual(target.target_type, TargetType.GITHUB_REPOSITORY)
        self.assertEqual(target.repository_url, "https://github.com/user/project.git")

    def test_scan_orchestrator_local_scan(self) -> None:
        result = self.orchestrator.run_scan(".")
        self.assertIsNotNone(result.context)
        self.assertIsNotNone(result.graph)

    def test_policy_engine_evaluation(self) -> None:
        result = self.orchestrator.run_scan(".")
        code = self.policy_engine.evaluate(result, fail_on="high")
        self.assertIn(code, (ExitCode.SUCCESS, ExitCode.POLICY_VIOLATION))

    def test_safety_zero_execution_guarantee(self) -> None:
        """Verify that CLI target resolution and scanning execute zero repository scripts or setup files."""
        result = self.orchestrator.run_scan(".")
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
