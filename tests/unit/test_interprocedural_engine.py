"""Unit tests for Step 34 — Advanced SAST & Interprocedural Analysis Engine."""

import os
import shutil
import tempfile
import unittest

from python_hunter.domain.ir.models import IRLocation
from python_hunter.domain.language.models import Language
from python_hunter.domain.semantics.cache_engine import AnalysisCacheEngine, AnalysisLimits
from python_hunter.domain.semantics.call_graph_2 import CallEdge, CallGraph2, CallKind
from python_hunter.domain.semantics.interprocedural_engine import (
    DataflowGraph,
    FlowStep,
    InterproceduralEngine,
    TaintFlowEvidence,
)
from python_hunter.domain.semantics.program_model import (
    ProgramCall,
    ProgramFunction,
    ProgramModel,
    ProgramModule,
    TypeInfo,
)
from python_hunter.domain.semantics.rule_dsl import DeclarativeSecurityRule
from python_hunter.domain.semantics.rule_engine_2 import ConfidenceEngine, RuleEngine2
from python_hunter.domain.semantics.security_context import (
    RoleLevel,
    SecurityContext,
    SecurityContextEngine,
    TrustBoundary,
)
from python_hunter.domain.semantics.symbol_table import NameResolver, ScopeKind, Symbol, SymbolKind, SymbolTable
from python_hunter.domain.semantics.taint_registries import (
    SanitizerContext,
    SanitizerDef,
    SanitizerRegistry,
    SinkCategory,
    SourceCategory,
    TaintSinkDef,
    TaintSinkRegistry,
    TaintSourceDef,
    TaintSourceRegistry,
)


class TestInterproceduralEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_program_model_and_symbol_table(self):
        model = ProgramModel()
        mod = ProgramModule(name="app", file_path="app.py", language=Language.PYTHON)
        func = ProgramFunction(name="handler", qualified_name="app.handler", module_name="app")
        mod.functions["app.handler"] = func
        model.add_module(mod)

        self.assertEqual(model.get_function("app.handler"), func)

        table = SymbolTable()
        sym = Symbol(
            name="user_input",
            qualified_name="app.handler.user_input",
            kind=SymbolKind.VARIABLE,
            scope_name="handler",
            type_info=TypeInfo(type_name="str", confidence=0.9, is_inferred=True),
        )
        table.add_symbol("handler", sym)
        looked = table.lookup_symbol("handler", "user_input")
        self.assertIsNotNone(looked)
        self.assertEqual(looked.type_info.type_name, "str")

    def test_name_resolver_conservative_dispatch(self):
        model = ProgramModel()
        table = SymbolTable()
        mod = ProgramModule(name="main", file_path="main.py", language=Language.PYTHON)

        f1 = ProgramFunction(name="process", qualified_name="mod1.process", module_name="mod1")
        f2 = ProgramFunction(name="process", qualified_name="mod2.process", module_name="mod2")

        mod.functions["mod1.process"] = f1
        mod.functions["mod2.process"] = f2
        model.add_module(mod)

        resolver = NameResolver(model, table)
        targets = resolver.resolve_call(f1, "process")
        self.assertGreaterEqual(len(targets), 2)
        self.assertIn("mod1.process", targets)
        self.assertIn("mod2.process", targets)

    def test_call_graph_2_reachable_paths(self):
        model = ProgramModel()
        table = SymbolTable()
        resolver = NameResolver(model, table)
        cg = CallGraph2(model, resolver)

        cg._add_edge(CallEdge("controller", "service", CallKind.DIRECT))
        cg._add_edge(CallEdge("service", "repository", CallKind.DIRECT))
        cg._add_edge(CallEdge("repository", "db_query", CallKind.DIRECT))

        paths = cg.reachable_paths("controller", "db_query")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["controller", "service", "repository", "db_query"])

    def test_taint_registries_and_context_sanitizer(self):
        sources = TaintSourceRegistry()
        sinks = TaintSinkRegistry()
        sanitizers = SanitizerRegistry()

        matched_src = sources.matches("request.args")
        self.assertGreaterEqual(len(matched_src), 1)

        matched_snk = sinks.matches("cursor.execute")
        self.assertGreaterEqual(len(matched_snk), 1)

        san = sanitizers.sanitizers["html_escape"]
        self.assertTrue(SanitizerContext.is_sanitizer_effective(san, SinkCategory.HTML_OUTPUT))
        self.assertFalse(SanitizerContext.is_sanitizer_effective(san, SinkCategory.SQL))

    def test_security_context_and_multi_tenant(self):
        sec_engine = SecurityContextEngine()
        ctx_unauth = SecurityContext(user_identity="anon", role=RoleLevel.ANONYMOUS, is_authenticated=False)

        violation = sec_engine.validate_context(
            ctx_unauth,
            sec_engine.invariants[0],  # sensitive_operation_requires_auth
            "auth.py",
            15,
        )
        self.assertIsNotNone(violation)
        self.assertIn("unauthenticated", violation.message)

    def test_confidence_engine_and_rule_engine_2(self):
        conf = ConfidenceEngine.calculate_confidence(
            has_type_info=True,
            has_exact_call_resolution=True,
            has_sanitizer_check=False,
            is_dynamic_dispatch=False,
        )
        self.assertEqual(conf.level, "HIGH")
        self.assertGreaterEqual(conf.score, 0.8)

        rule_dict = {
            "rule_id": "PYH-R2-001",
            "version": "1.1.0",
            "title": "Custom Declarative Rule",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "remediation": "Sanitize query input.",
        }
        rule = DeclarativeSecurityRule.from_dict(rule_dict)
        self.assertEqual(rule.rule_id, "PYH-R2-001")

    def test_cache_engine_invalidation(self):
        limits = AnalysisLimits(max_call_depth=5)
        cache = AnalysisCacheEngine(limits)

        file_path = os.path.join(self.temp_dir, "test.py")
        with open(file_path, "w") as f:
            f.write("def foo(): pass\n")

        hash1 = cache.get_workspace_hash(self.temp_dir)
        cache.store_cached_analysis(self.temp_dir, {"rule": "1.0"}, {"model": "data"})

        cached = cache.get_cached_analysis(self.temp_dir, {"rule": "1.0"})
        self.assertIsNotNone(cached)

        # Modify file -> should invalidate
        with open(file_path, "w") as f:
            f.write("def foo(): print('modified')\n")

        invalidated = cache.get_cached_analysis(self.temp_dir, {"rule": "1.0"})
        self.assertIsNone(invalidated)


if __name__ == "__main__":
    unittest.main()
