"""Unit tests for Secret Detection Engine, Entropy, Redaction, and Registry."""

import unittest

from python_hunter.detectors.secrets import create_default_secret_registry
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.domain.secrets.entropy import EntropyCalculator
from python_hunter.domain.secrets.placeholders import PlaceholderFilter
from python_hunter.domain.secrets.redaction import Redactor
from python_hunter.domain.secrets.registry import SecretDetectorRegistry


from python_hunter.domain.projects.project import Project


class TestSecretEngineAndUtilities(unittest.TestCase):
    """Test suite covering Entropy, Redaction, Placeholders, Registry, and Engine."""

    def test_entropy_calculator(self) -> None:
        low_entropy = EntropyCalculator.calculate("aaaaaaaaaaaaaaaa")
        high_entropy = EntropyCalculator.calculate("a8f9B!z$k2Q#m9Xp")
        self.assertLess(low_entropy, 1.0)
        self.assertGreater(high_entropy, 3.5)

    def test_redactor_redact_value(self) -> None:
        short_val = Redactor.redact_value("secret")
        self.assertEqual(short_val, "[REDACTED]")

        long_val = Redactor.redact_value("ak_mock_1234567890abcdef")
        self.assertTrue(long_val.startswith("ak_m"))
        self.assertTrue(long_val.endswith("cdef"))
        self.assertNotIn("1234567890", long_val)

    def test_placeholder_filter(self) -> None:
        self.assertTrue(PlaceholderFilter.is_placeholder("YOUR_API_KEY"))
        self.assertTrue(PlaceholderFilter.is_placeholder("replace_me"))
        self.assertTrue(PlaceholderFilter.is_placeholder("changeme"))
        self.assertTrue(PlaceholderFilter.is_placeholder("xxxxxxxxxxxxxxxx"))
        self.assertFalse(PlaceholderFilter.is_placeholder("ak_mock_99887766554433221100aabb"))

    def test_secret_registry(self) -> None:
        registry = create_default_secret_registry()
        self.assertGreaterEqual(len(registry.enabled_detectors()), 10)
        self.assertIsNotNone(registry.get("PYH-SECRET-001"))

    def test_secret_engine_scan_file(self) -> None:
        engine = SecretDetectionEngine(registry=create_default_secret_registry())
        project = Project(name="test", root_path="/tmp")
        context = AnalysisContext(scan_id="test-scan", project=project)

        content = 'API_KEY = "ak_mock_99887766554433221100aabb"\n'
        findings = engine.scan_file("config.py", content, context)

        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "PYH-SECRET-001")
        self.assertNotIn("ak_mock_99887766554433221100aabb", finding.evidence)
        self.assertIn("ak_m", finding.evidence)


if __name__ == "__main__":
    unittest.main()
