"""Unit tests for Call Graph domain models."""

import unittest

from python_hunter.domain.ast.models import ASTLocation
from python_hunter.domain.callgraph.models import (
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    CFGNodeType,
    CallEdge,
    CallEdgeType,
    ControlFlowGraph,
    EntryPoint,
    EntryPointType,
    Symbol,
    SymbolType,
)


class TestCallGraphModels(unittest.TestCase):
    """Test suite for Call Graph domain entities."""

    def test_symbol_instantiation(self) -> None:
        loc = ASTLocation(file_path="app/service.py", line_start=15, column_start=4)
        sym = Symbol(
            name="create_user",
            qualified_name="app.service.UserService.create_user",
            symbol_type=SymbolType.METHOD,
            file_path="app/service.py",
            location=loc,
            parameters=["self", "data"],
        )
        self.assertEqual(sym.qualified_name, "app.service.UserService.create_user")
        self.assertEqual(sym.symbol_type, SymbolType.METHOD)

    def test_call_edge_creation(self) -> None:
        edge = CallEdge(
            caller_qualified_name="app.routes.get_user",
            callee_qualified_name="app.service.UserService.create_user",
            edge_type=CallEdgeType.METHOD,
        )
        self.assertEqual(edge.caller_qualified_name, "app.routes.get_user")
        self.assertEqual(edge.callee_qualified_name, "app.service.UserService.create_user")

    def test_cfg_construction(self) -> None:
        cfg = ControlFlowGraph(function_qualified_name="app.utils.helper")
        n0 = CFGNode(node_id=0, node_type=CFGNodeType.ENTRY, label="ENTRY")
        n1 = CFGNode(node_id=1, node_type=CFGNodeType.EXIT, label="EXIT")
        cfg.nodes[0] = n0
        cfg.nodes[1] = n1
        cfg.edges.append(CFGEdge(source_id=0, target_id=1, edge_type=CFGEdgeType.NORMAL))

        self.assertEqual(len(cfg.nodes), 2)
        self.assertEqual(len(cfg.edges), 1)


if __name__ == "__main__":
    unittest.main()
