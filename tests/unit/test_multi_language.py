"""Unit tests for Multi-Language Architecture, LanguageDetector, Registry, and IR."""

import unittest
from python_hunter.domain.discovery.language_detector import LanguageDetector
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.models import AnalyzerCapability, Language
from python_hunter.domain.language.registry import LanguageRegistry


class TestMultiLanguageArchitecture(unittest.TestCase):
    """Unit test suite for LanguageRegistry, LanguageDetector, and SecurityIR."""

    def setUp(self) -> None:
        self.detector = LanguageDetector()
        self.registry = LanguageRegistry()

    def test_language_registry(self) -> None:
        py_adapter = self.registry.get_adapter(Language.PYTHON)
        self.assertIsNotNone(py_adapter)
        self.assertTrue(py_adapter.is_available())
        self.assertTrue(py_adapter.capabilities.supports(AnalyzerCapability.TAINT))

        js_adapter = self.registry.get_adapter(Language.JAVASCRIPT)
        self.assertIsNotNone(js_adapter)
        self.assertTrue(js_adapter.is_available())

    def test_language_detector_python(self) -> None:
        langs = self.detector.detect_languages(".")
        self.assertIn(Language.PYTHON, langs)

    def test_security_ir_initialization(self) -> None:
        ir = SecurityIR(language=Language.PYTHON)
        self.assertEqual(ir.language, Language.PYTHON)
        self.assertEqual(ir.ir_version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
