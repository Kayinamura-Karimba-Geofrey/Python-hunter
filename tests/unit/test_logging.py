"""Unit tests for Structured Logger."""

import unittest
from python_hunter.infrastructure.observability.logging import Logger, redact_secrets


class TestStructuredLogging(unittest.TestCase):
    """Test suite for Logger formatting and secret redaction."""

    def test_secret_redaction(self) -> None:
        """Verify sensitive credentials and API keys are redacted from logs."""
        raw_msg = "User logged in with api_key: secret_12345_token"
        clean_msg = redact_secrets(raw_msg)
        self.assertNotIn("secret_12345_token", clean_msg)
        self.assertIn("[REDACTED]", clean_msg)

    def test_logger_instantiation(self) -> None:
        """Verify logger instantiation and level filtering."""
        logger = Logger(name="test-logger", level="INFO")
        self.assertEqual(logger.name, "test-logger")
        self.assertEqual(logger.current_level, 20)


if __name__ == "__main__":
    unittest.main()
