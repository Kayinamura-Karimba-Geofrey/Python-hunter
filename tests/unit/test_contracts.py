"""Unit tests for Analyzer and Pipeline Abstraction Contracts."""

import unittest
from python_hunter.domain.analysis.base import Analyzer
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.analysis.result import AnalysisResult
from python_hunter.domain.common.enums import Category
from python_hunter.domain.projects.project import Project


class DummyAnalyzer(Analyzer):
    """Test concrete implementation of abstract Analyzer contract."""

    @property
    def name(self) -> str:
        return "dummy-analyzer"

    @property
    def category(self) -> Category:
        return Category.CODE_INJECTION

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        return AnalysisResult(analyzer_name=self.name, findings=[], duration_ms=12.5)


class TestAnalyzerContracts(unittest.TestCase):
    """Test suite for Analyzer abstract contracts and result containers."""

    def test_analyzer_instantiation(self) -> None:
        """Verify concrete Analyzer contract compliance."""
        analyzer = DummyAnalyzer()
        self.assertEqual(analyzer.name, "dummy-analyzer")
        self.assertEqual(analyzer.category, Category.CODE_INJECTION)

        project = Project(name="test-project", root_path="/tmp")
        context = AnalysisContext(scan_id="test-scan-id", project=project)

        result = analyzer.analyze(context)
        self.assertEqual(result.analyzer_name, "dummy-analyzer")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.duration_ms, 12.5)


if __name__ == "__main__":
    unittest.main()
