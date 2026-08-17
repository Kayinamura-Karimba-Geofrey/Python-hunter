"""Unit tests for Centralized Configuration System."""

import unittest
from python_hunter.domain.exceptions import ConfigurationError
from python_hunter.infrastructure.config.settings import LogConfig, ScanConfig, Settings


class TestConfiguration(unittest.TestCase):
    """Test suite for Settings loading and validation."""

    def test_default_settings(self) -> None:
        """Verify default configuration settings."""
        settings = Settings.load_from_env({})
        self.assertEqual(settings.app.env, "development")
        self.assertTrue(settings.app.debug)
        self.assertEqual(settings.log.level, "INFO")
        self.assertEqual(settings.scan.max_file_size_mb, 10)
        self.assertEqual(settings.scan.timeout_seconds, 300)

    def test_environment_variable_overrides(self) -> None:
        """Verify environment variable overrides with PYH_ prefix."""
        env = {
            "PYH_ENV": "production",
            "PYH_DEBUG": "false",
            "PYH_LOG_LEVEL": "DEBUG",
            "PYH_MAX_SCAN_FILE_SIZE_MB": "50",
            "PYH_SCAN_TIMEOUT_SECONDS": "600",
        }
        settings = Settings.load_from_env(env)
        self.assertEqual(settings.app.env, "production")
        self.assertFalse(settings.app.debug)
        self.assertEqual(settings.log.level, "DEBUG")
        self.assertEqual(settings.scan.max_file_size_mb, 50)
        self.assertEqual(settings.scan.timeout_seconds, 600)

    def test_invalid_log_level_validation(self) -> None:
        """Verify invalid log level raises ConfigurationError."""
        with self.assertRaises(ConfigurationError):
            LogConfig(level="INVALID_LEVEL")

    def test_invalid_scan_limits_validation(self) -> None:
        """Verify invalid scan limits raise ConfigurationError."""
        with self.assertRaises(ConfigurationError):
            ScanConfig(max_file_size_mb=-5)

        with self.assertRaises(ConfigurationError):
            ScanConfig(timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
