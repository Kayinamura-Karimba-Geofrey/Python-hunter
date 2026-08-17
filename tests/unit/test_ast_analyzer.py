"""Unit tests for ASTAnalyzer concrete implementation."""

import unittest
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Category
from python_hunter.domain.projects.project import Project
from python_hunter.domain.projects.target_file import TargetFile
from python_hunter.infrastructure.ast.ast_analyzer import ASTAnalyzer


class TestASTAnalyzer(unittest.TestCase):
    """Test suite for concrete ASTAnalyzer class."""

    def test_analyzer_contract_properties(self) -> None:
        """Verify ASTAnalyzer implements Analyzer contract properties."""
        analyzer = ASTAnalyzer()
        self.assertEqual(analyzer.name, "ast-analyzer")
        self.assertEqual(analyzer.category, Category.CODE_INJECTION)

    def test_analyzer_execution(self) -> None:
        """Verify ASTAnalyzer execution on dummy target files."""
        analyzer = ASTAnalyzer()
        project = Project(name="dummy", root_path="/tmp")
        context = AnalysisContext(
            scan_id="scan-123",
            project=project,
            target_files=[
                TargetFile(relative_path="main.py", size_bytes=10, mime_type="text/x-python", is_python=True)
            ],
        )
        result = analyzer.analyze(context)
        self.assertEqual(result.analyzer_name, "ast-analyzer")
        self.assertIn("documents_count", result.metadata)


if __name__ == "__main__":
    unittest.main()
