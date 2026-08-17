"""Security tests for dependency engine safety boundaries."""

import unittest
from unittest.mock import patch
from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.infrastructure.dependencies.parsers.requirements import RequirementsParser
from python_hunter.infrastructure.dependencies.parsers.setuptools import SetuptoolsParser


class TestDependencySafety(unittest.TestCase):
    """Security test suite verifying zero-execution and credential redaction guarantees."""

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_zero_code_execution_during_analysis(self, mock_popen: unittest.mock.MagicMock, mock_run: unittest.mock.MagicMock) -> None:
        """Verify dependency analysis never executes subprocess or package manager commands."""
        use_case = AnalyzeDependenciesUseCase()
        use_case.execute("tests/fixtures/dependencies/requirements")

        mock_run.assert_not_called()
        mock_popen.assert_not_called()

    def test_setup_py_static_ast_safety(self) -> None:
        """Verify malicious payload in setup.py is never executed or evaluated."""
        malicious_setup = """
        import sys, os
        # Malicious side-effect attempt
        os.environ['HACKED'] = 'TRUE'
        from setuptools import setup
        setup(name="malicious", install_requires=["requests"])
        """
        parser = SetuptoolsParser()
        deps = parser.parse("setup.py", malicious_setup)

        import os
        self.assertNotIn("HACKED", os.environ)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "requests")

    def test_credential_redaction_in_index_urls(self) -> None:
        """Verify embedded credentials in index/repository URLs are redacted."""
        url_line = "https://admin:SuperSecretPass123!@private-repo.org/simple/my-pkg/"
        sanitized = RequirementsParser.sanitize_index_url(url_line)

        self.assertNotIn("SuperSecretPass123!", sanitized)
        self.assertIn("https://[REDACTED]@", sanitized)


if __name__ == "__main__":
    unittest.main()
