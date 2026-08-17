"""Unit tests for Call Graph Engine."""

import unittest

from python_hunter.domain.ast.models import ASTDocument, FunctionInfo, CallInfo, DecoratorInfo
from python_hunter.domain.callgraph.engine import CallGraphEngine
from python_hunter.domain.callgraph.models import CallEdge, EntryPointType, SymbolType


class TestCallGraphEngine(unittest.TestCase):
    """Test suite for CallGraphEngine symbol indexing, call graph construction, and reachability."""

    def setUp(self) -> None:
        self.engine = CallGraphEngine()

    def test_symbol_indexing_and_call_resolution(self) -> None:
        fn_main = FunctionInfo(name="main_route", qualified_name="app.main_route", decorators=[DecoratorInfo(name="app.get")])
        fn_service = FunctionInfo(name="process_data", qualified_name="app.process_data")
        call_info = CallInfo(name="process_data", qualified_name="app.process_data")

        doc = ASTDocument(
            file_path="app.py",
            module_name="app",
            functions=[fn_main, fn_service],
            calls=[call_info],
        )

        res = self.engine.analyze_documents([doc])
        self.assertIn("app.main_route", res["symbols"])
        self.assertIn("app.process_data", res["symbols"])
        self.assertEqual(len(res["call_edges"]), 1)
        self.assertEqual(res["call_edges"][0].callee_qualified_name, "app.process_data")

    def test_entry_point_discovery(self) -> None:
        fn_route = FunctionInfo(name="get_users", qualified_name="app.get_users", decorators=[DecoratorInfo(name="route")])
        doc = ASTDocument(file_path="app.py", module_name="app", functions=[fn_route])

        res = self.engine.analyze_documents([doc])
        self.assertEqual(len(res["entry_points"]), 1)
        self.assertEqual(res["entry_points"][0].entry_type, EntryPointType.HTTP_ROUTE)

    def test_strongly_connected_components_recursion(self) -> None:
        self.engine.call_edges.append(
            CallEdge(caller_qualified_name="app.func_a", callee_qualified_name="app.func_b")
        )
        self.engine.call_edges.append(
            CallEdge(caller_qualified_name="app.func_b", callee_qualified_name="app.func_a")
        )

        sccs = self.engine._find_strongly_connected_components()
        self.assertEqual(len(sccs), 1)

    def test_dot_export(self) -> None:
        doc = ASTDocument(
            file_path="app.py",
            module_name="app",
            functions=[FunctionInfo(name="a", qualified_name="app.a"), FunctionInfo(name="b", qualified_name="app.b")],
            calls=[CallInfo(name="b", qualified_name="app.b")],
        )
        self.engine.analyze_documents([doc])
        dot = self.engine.export_dot()
        self.assertIn("digraph CallGraph", dot)
        self.assertIn('"app" -> "app.b";', dot)


if __name__ == "__main__":
    unittest.main()
