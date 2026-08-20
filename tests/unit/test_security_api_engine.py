"""Unit tests for Step 30 Security Intelligence API & Developer Layer (without hard external web dependencies)."""

import unittest
from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestSecurityApiEngine(unittest.TestCase):
    """Test suite for SecurityApplicationService, system info, scan jobs, and CLI/API application layer parity."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_system_info_service(self) -> None:
        info = self.app_service.get_system_info()
        self.assertIn("Python Hunter", info["name"])
        self.assertEqual(info["status"], "OPERATIONAL")
        self.assertIn("Python", info["supported_languages"])

    def test_execute_scan_service(self) -> None:
        res = self.app_service.execute_scan(".", profile="strict")
        self.assertIn("findings_count", res)
        self.assertIn("risk_score", res)
        self.assertIn("gate_status", res)
        self.assertIn("exit_code", res)


if __name__ == "__main__":
    unittest.main()
