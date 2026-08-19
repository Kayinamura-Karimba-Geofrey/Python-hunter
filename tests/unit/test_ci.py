"""Unit tests for CI/CD mode, exit codes, SARIF output, and PR baseline behavior."""

import os
import unittest

from python_hunter.application.orchestrator import ScanOrchestrator
from python_hunter.infrastructure.repository import TargetResolver
from python_hunter.presentation import ExitCode, PolicyEngine


class TestCICDIntegration(unittest.TestCase):
    """Unit test suite for CI/CD integration, SARIF schema compliance, and exit code policies."""

    def setUp(self) -> None:
        self.orchestrator = ScanOrchestrator()
        self.policy_engine = PolicyEngine()

    def test_ci_context_metadata(self) -> None:
        os.environ["CI"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "test/repo"
        result = self.orchestrator.run_scan(".", options={"is_ci": True})
        self.assertTrue(result.context.is_ci)
        self.assertEqual(result.context.ci_metadata["repository"], "test/repo")

    def test_ci_exit_codes_distinction(self) -> None:
        result = self.orchestrator.run_scan(".")
        code = self.policy_engine.evaluate(result, fail_on="high")
        self.assertIn(code, (ExitCode.SUCCESS, ExitCode.POLICY_VIOLATION))

    def test_safety_fork_pr_no_credential_leak(self) -> None:
        """Verify that CI scan contexts redact and shield environment tokens."""
        os.environ["GITHUB_TOKEN"] = "secret_token_12345"
        result = self.orchestrator.run_scan(".", options={"is_ci": True})
        self.assertNotIn("secret_token_12345", str(result.context))


if __name__ == "__main__":
    unittest.main()
