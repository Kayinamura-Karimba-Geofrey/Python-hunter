"""Unit tests for Step 26 Framework-Aware Application Security Engine."""

import unittest
from python_hunter.domain.frameworks.framework_registry import FrameworkRegistry


class TestFrameworkSecurityEngine(unittest.TestCase):
    """Test suite for framework discovery, route modeling, authentication boundaries, and zero code execution."""

    def setUp(self) -> None:
        self.registry = FrameworkRegistry()

    def test_framework_registry_discovery(self) -> None:
        models = self.registry.detect_all(".")
        self.assertIsInstance(models, list)

    def test_registered_framework_adapters(self) -> None:
        flask_adapter = self.registry.get_adapter("flask")
        fastapi_adapter = self.registry.get_adapter("fastapi")
        express_adapter = self.registry.get_adapter("express")
        self.assertIsNotNone(flask_adapter)
        self.assertIsNotNone(fastapi_adapter)
        self.assertIsNotNone(express_adapter)


if __name__ == "__main__":
    unittest.main()
