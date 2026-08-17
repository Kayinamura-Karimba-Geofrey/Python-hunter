"""Unit tests for Domain Exception hierarchy."""

import unittest
from python_hunter.domain.exceptions import (
    AnalyzerError,
    ConfigurationError,
    InfrastructureError,
    ProjectError,
    PythonHunterError,
    RuleError,
    ScanError,
    ValidationError,
)


class TestDomainExceptions(unittest.TestCase):
    """Test suite for domain exception inheritance and message formatting."""

    def test_exception_inheritance(self) -> None:
        """Verify all custom exceptions inherit from PythonHunterError."""
        self.assertTrue(issubclass(ConfigurationError, PythonHunterError))
        self.assertTrue(issubclass(ProjectError, PythonHunterError))
        self.assertTrue(issubclass(ScanError, PythonHunterError))
        self.assertTrue(issubclass(AnalyzerError, PythonHunterError))
        self.assertTrue(issubclass(RuleError, PythonHunterError))
        self.assertTrue(issubclass(ValidationError, PythonHunterError))
        self.assertTrue(issubclass(InfrastructureError, PythonHunterError))

    def test_exception_details(self) -> None:
        """Verify exception formatting retains string message and details dict."""
        err = ScanError("Invalid transition", details={"from": "COMPLETED", "to": "RUNNING"})
        self.assertEqual(err.message, "Invalid transition")
        self.assertEqual(err.details["from"], "COMPLETED")
        self.assertIn("details:", str(err))


if __name__ == "__main__":
    unittest.main()
