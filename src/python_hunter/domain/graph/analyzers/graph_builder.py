"""Whole-Project Security Knowledge Graph Builder Implementation."""

import ast
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.graph.analyzers.base import BaseGraphBuilder
from python_hunter.domain.graph.models import EdgeType, NodeType, SecurityEdge, SecurityGraph, SecurityNode


class WholeProjectGraphBuilder(BaseGraphBuilder):
    """Builds unified whole-project security knowledge graph connecting modules, functions, routes, sinks, and controls."""

    def build_graph(self, documents: list[ASTDocument], graph: SecurityGraph) -> None:
        # Create Root Project Node
        proj_node = SecurityNode(
            id="node:project:root",
            type=NodeType.PROJECT,
            name="PythonHunterProject",
            risk_score=10.0,
            confidence=Confidence.HIGH,
        )
        graph.add_node(proj_node)

        for doc in documents:
            mod_id = f"node:module:{doc.file_path}"
            mod_node = SecurityNode(
                id=mod_id,
                type=NodeType.MODULE,
                name=doc.file_path,
                file_path=doc.file_path,
                risk_score=10.0,
                confidence=Confidence.HIGH,
            )
            graph.add_node(mod_node)
            graph.add_edge(
                SecurityEdge(
                    source_id="node:project:root",
                    target_id=mod_id,
                    relationship=EdgeType.CONTAINS,
                    evidence="Project Module",
                )
            )

            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_id = f"node:fn:{doc.file_path}:{node.name}"
                    fn_node = SecurityNode(
                        id=fn_id,
                        type=NodeType.FUNCTION,
                        name=node.name,
                        file_path=doc.file_path,
                        location=Location(line_start=node.lineno, line_end=node.lineno, column_start=node.col_offset),
                        risk_score=20.0,
                        confidence=Confidence.HIGH,
                    )
                    graph.add_node(fn_node)
                    graph.add_edge(
                        SecurityEdge(
                            source_id=mod_id,
                            target_id=fn_id,
                            relationship=EdgeType.CONTAINS,
                            evidence="Function Definition",
                        )
                    )

                    # Check for security sinks or routes inside function
                    fn_code = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if any(sink in fn_code for sink in ("execute(", "system(", "eval(", "requests.post(", "call(", "subprocess.")):
                        sink_id = f"node:sink:{doc.file_path}:{node.name}"
                        sink_node = SecurityNode(
                            id=sink_id,
                            type=NodeType.TAINT_SINK,
                            name=f"Sink in {node.name}",
                            file_path=doc.file_path,
                            risk_score=85.0,
                            confidence=Confidence.HIGH,
                        )
                        graph.add_node(sink_node)
                        graph.add_edge(
                            SecurityEdge(
                                source_id=fn_id,
                                target_id=sink_id,
                                relationship=EdgeType.FLOWS_TO,
                                evidence="Dataflow to Sink",
                            )
                        )
