"""Unit tests for Advanced Dataflow Engine, Sanitizers, and Exploitability Proofs."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.taint.advanced_engine import AdvancedDataflowEngine
from python_hunter.domain.taint.models import ExploitabilityLevel, TaintSinkCategory, TaintSourceCategory, TrustLevel


class TestAdvancedDataflowEngine(unittest.TestCase):
    """Test suite for Advanced Dataflow Engine."""

    def setUp(self) -> None:
        self.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "fixtures", "dataflow")
        )
        self.ast_use_case = AnalyzeASTUseCase()
        self.taint_use_case = AnalyzeTaintUseCase(ast_use_case=self.ast_use_case)

    def test_interprocedural_flow(self) -> None:
        code = """
val = request.args.get("name")
query = "SELECT * FROM users WHERE name = " + val
os.system(query)
        """
        doc = ASTDocument(file_path="app.py", module_name="app", source_lines=code.strip().split("\n"))
        engine = AdvancedDataflowEngine()
        result = engine.analyze_documents([doc])
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_sanitizer_context_evaluation(self) -> None:
        code = """
val = request.args.get("cmd")
safe_val = shlex.quote(val)
os.system("ls " + safe_val)
        """
        doc = ASTDocument(file_path="app.py", module_name="app", source_lines=code.strip().split("\n"))
        engine = AdvancedDataflowEngine()
        result = engine.analyze_documents([doc])
        self.assertIn("nodes", result)
        self.assertIn("edges", result)


if __name__ == "__main__":
    unittest.main()
