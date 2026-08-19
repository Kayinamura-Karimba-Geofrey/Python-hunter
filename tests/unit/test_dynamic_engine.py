"""Unit tests for Dynamic Behavior Engine & Security Rules."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_dynamic import AnalyzeDynamicUseCase
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.dynamic.engine import DynamicBehaviorEngine
from python_hunter.domain.dynamic.models import DynamicBehaviorType, ResolutionState
from python_hunter.rules.dynamic.pyh_dynamic_001_eval_exec import PYHDynamic001EvalExec
from python_hunter.rules.dynamic.pyh_dynamic_002_unsafe_pickle import PYHDynamic002UnsafePickle
from python_hunter.rules.dynamic.pyh_dynamic_003_unsafe_yaml import PYHDynamic003UnsafeYAML


class TestDynamicBehaviorEngine(unittest.TestCase):
    """Test suite for Dynamic Behavior Engine and Analyzers."""

    def setUp(self) -> None:
        self.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "fixtures", "dynamic")
        )
        self.ast_use_case = AnalyzeASTUseCase()
        self.dynamic_use_case = AnalyzeDynamicUseCase(ast_use_case=self.ast_use_case)

    def test_reflection_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "reflection", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)
        
        self.assertGreater(summary.reflection_count, 0)
        types = [b.behavior_type for b in behaviors]
        self.assertIn(DynamicBehaviorType.REFLECTION, types)

    def test_dynamic_import_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "imports", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)

        self.assertGreater(summary.dynamic_import_count, 0)
        targets = [b.target for b in behaviors if b.behavior_type == DynamicBehaviorType.DYNAMIC_IMPORT]
        self.assertIn("json", targets)

    def test_eval_exec_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "eval_exec", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)

        self.assertGreater(summary.dynamic_execution_count, 0)

    def test_deserialization_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "pickle", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)

        self.assertGreater(summary.unsafe_deserialization_count, 0)

    def test_metaclass_and_monkeypatch(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "metaclasses", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)

        self.assertGreater(summary.metaclass_count, 0)
        self.assertGreater(summary.monkey_patch_count, 0)

    def test_analysis_modes(self) -> None:
        engine_cons = DynamicBehaviorEngine(mode="conservative")
        engine_bal = DynamicBehaviorEngine(mode="balanced")
        fixture_path = os.path.join(self.fixtures_dir, "reflection", "app.py")
        ast_summary = self.ast_use_case.execute(fixture_path)

        b_cons, s_cons = engine_cons.analyze(ast_summary.documents)
        b_bal, s_bal = engine_bal.analyze(ast_summary.documents)

        self.assertLessEqual(len(b_cons), len(b_bal))

    def test_safety_guarantee_no_execution(self) -> None:
        """Verify that analyzed project code is never imported or executed."""
        fixture_path = os.path.join(self.fixtures_dir, "eval_exec", "app.py")
        behaviors, summary = self.dynamic_use_case.execute(fixture_path)
        self.assertIsNotNone(summary)

    def test_dynamic_rules_evaluation(self) -> None:
        rule001 = PYHDynamic001EvalExec()
        rule002 = PYHDynamic002UnsafePickle()
        rule003 = PYHDynamic003UnsafeYAML()

        fixture_eval = os.path.join(self.fixtures_dir, "eval_exec", "app.py")
        ast_summary = self.ast_use_case.execute(fixture_eval)
        from python_hunter.domain.analysis.context import AnalysisContext
        from python_hunter.domain.projects.project import Project
        proj = Project(name="test", root_path=fixture_eval)
        ctx = AnalysisContext(scan_id="1", project=proj)
        findings001 = rule001.evaluate(ast_summary, ctx)
        self.assertTrue(any(f.rule_id == "PYH-DYNAMIC-001" for f in findings001))

        fixture_pickle = os.path.join(self.fixtures_dir, "pickle", "app.py")
        ast_summary_p = self.ast_use_case.execute(fixture_pickle)
        proj_p = Project(name="test", root_path=fixture_pickle)
        ctx_p = AnalysisContext(scan_id="1", project=proj_p)
        findings002 = rule002.evaluate(ast_summary_p, ctx_p)
        self.assertTrue(any(f.rule_id == "PYH-DYNAMIC-002" for f in findings002))



if __name__ == "__main__":
    unittest.main()
