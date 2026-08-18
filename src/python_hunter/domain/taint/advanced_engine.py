"""Advanced Dataflow, Interprocedural Taint, Object/Container Flow, and Exploitability Analysis Engine."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument, ASTLocation
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.taint.config import TaintConfig
from python_hunter.domain.taint.models import (
    DataflowEdge,
    DataflowEdgeType,
    DataflowNode,
    DataflowNodeKind,
    ExploitabilityLevel,
    ExploitabilityProof,
    FunctionSummary,
    SanitizationContext,
    SanitizerRegistry,
    TaintFlow,
    TaintNode,
    TaintSinkCategory,
    TaintSourceCategory,
    TaintStateEnum,
    TrustLevel,
    ValidatorRegistry,
)


class AdvancedDataflowEngine:
    """Static Dataflow Analysis Engine for Interprocedural Taint, Objects, Containers, and Exploitability Proofs."""

    def __init__(self, config: TaintConfig | None = None) -> None:
        self.config = config or TaintConfig()
        self.sanitizer_registry = SanitizerRegistry()
        self.validator_registry = ValidatorRegistry()
        self.nodes: dict[str, DataflowNode] = {}
        self.edges: list[DataflowEdge] = []
        self.function_summaries: dict[str, FunctionSummary] = {}

    def analyze_documents(self, documents: list[ASTDocument]) -> dict[str, Any]:
        """Perform comprehensive dataflow analysis across all AST documents."""
        self.nodes.clear()
        self.edges.clear()

        # Step 1: Extract flow nodes and edges from ASTs
        for doc in documents:
            if doc.source_lines:
                try:
                    tree = ast.parse("\n".join(doc.source_lines))
                    self._analyze_ast_tree(doc, tree)
                except Exception:
                    continue

        # Step 2: Build exploitability proofs for detected flows
        flows = self._evaluate_flows(documents)

        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "flows": flows,
            "summaries": self.function_summaries,
        }

    def _analyze_ast_tree(self, doc: ASTDocument, tree: ast.AST) -> None:
        visitor = DataflowASTVisitor(doc, self)
        visitor.visit(tree)

    def _evaluate_flows(self, documents: list[ASTDocument]) -> list[TaintFlow]:
        flows: list[TaintFlow] = []
        # Find all SOURCE nodes and trace paths to SINK nodes
        source_nodes = [n for n in self.nodes.values() if n.kind == DataflowNodeKind.SOURCE]
        sink_nodes = [n for n in self.nodes.values() if n.kind == DataflowNodeKind.SINK]

        for src in source_nodes:
            for sink in sink_nodes:
                path = self._find_path(src.id, sink.id)
                if path:
                    flow = self._build_taint_flow(src, sink, path)
                    flows.append(flow)

        return flows

    def _find_path(self, start_id: str, end_id: str) -> list[DataflowNode] | None:
        visited = set()
        queue = [[start_id]]

        while queue:
            path_ids = queue.pop(0)
            node_id = path_ids[-1]

            if node_id == end_id:
                return [self.nodes[nid] for nid in path_ids if nid in self.nodes]

            if node_id not in visited:
                visited.add(node_id)
                outgoing = [e.target_id for e in self.edges if e.source_id == node_id]
                for next_id in outgoing:
                    new_path = list(path_ids)
                    new_path.append(next_id)
                    queue.append(new_path)

        return None

    def _build_taint_flow(
        self, src_node: DataflowNode, sink_node: DataflowNode, path: list[DataflowNode]
    ) -> TaintFlow:
        src_cat_str = src_node.metadata.get("category", TaintSourceCategory.HTTP_REQUEST.value)
        try:
            src_cat = TaintSourceCategory(src_cat_str)
        except ValueError:
            src_cat = TaintSourceCategory.HTTP_REQUEST

        sink_cat_str = sink_node.metadata.get("category", TaintSinkCategory.SQL_INJECTION.value)
        try:
            sink_cat = TaintSinkCategory(sink_cat_str)
        except ValueError:
            sink_cat = TaintSinkCategory.SQL_INJECTION

        flow_nodes = [
            TaintNode(
                label=n.symbol,
                location=n.location,
                node_type=n.kind.value.lower(),
                description=n.metadata.get("description", ""),
            )
            for n in path
        ]

        sanitizers_applied = []
        validations_applied = []
        transformations_applied = []

        for n in path:
            if n.kind == DataflowNodeKind.SANITIZATION:
                sanitizers_applied.append((n.symbol, sink_cat.required_sanitization_context))
            elif n.kind == DataflowNodeKind.VALIDATION:
                validations_applied.append(n.symbol)
            elif n.kind == DataflowNodeKind.TRANSFORMATION:
                transformations_applied.append(n.symbol)

        is_sanitized = len(sanitizers_applied) > 0
        is_validated = len(validations_applied) > 0

        if is_sanitized:
            exploitability = ExploitabilityLevel.NOT_EXPLOITABLE
        elif is_validated:
            exploitability = ExploitabilityLevel.UNLIKELY
        else:
            exploitability = ExploitabilityLevel.HIGHLY_LIKELY if src_cat == TaintSourceCategory.HTTP_REQUEST else ExploitabilityLevel.POTENTIAL

        proof = ExploitabilityProof(
            entry_point=path[0].function_name or "global",
            source_description=src_node.symbol,
            source_category=src_cat,
            trust_level=TrustLevel.UNTRUSTED if src_cat == TaintSourceCategory.HTTP_REQUEST else TrustLevel.INTERNAL,
            transformations=transformations_applied,
            validations=validations_applied,
            sanitizers=[s[0] for s in sanitizers_applied],
            sink_description=sink_node.symbol,
            sink_category=sink_cat,
            preconditions=["Input controlled by caller"],
            exploitability=exploitability,
            confidence=Confidence.HIGH,
            evidence_nodes=path,
        )

        return TaintFlow(
            source_node=flow_nodes[0],
            sink_node=flow_nodes[-1],
            sink_category=sink_cat,
            source_category=src_cat,
            flow_path=flow_nodes,
            transformations=transformations_applied,
            applied_sanitizers=sanitizers_applied,
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
            proof=proof,
        )


class DataflowASTVisitor(ast.NodeVisitor):
    """AST Visitor constructing Dataflow Nodes and Edges for Python statements/expressions."""

    def __init__(self, doc: ASTDocument, engine: AdvancedDataflowEngine) -> None:
        self.doc = doc
        self.engine = engine
        self.current_function: str | None = None
        self.var_node_map: dict[str, str] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_fn = self.current_function
        self.current_function = node.name
        for arg in node.args.args:
            param_id = f"{node.name}:{arg.arg}"
            df_node = DataflowNode(
                id=param_id,
                kind=DataflowNodeKind.PARAMETER,
                symbol=arg.arg,
                function_name=node.name,
                taint_state=TaintStateEnum.UNKNOWN,
            )
            self.engine.nodes[param_id] = df_node
            self.var_node_map[arg.arg] = param_id

        self.generic_visit(node)
        self.current_function = old_fn

    def visit_Assign(self, node: ast.Assign) -> None:
        # Evaluate RHS
        rhs_id = self._process_expr(node.value)

        # Evaluate LHS targets
        for target in node.targets:
            lhs_name = self._get_name(target)
            if lhs_name and rhs_id:
                loc = ASTLocation(
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    column_start=node.col_offset,
                    column_end=node.end_col_offset or node.col_offset,
                )
                target_id = f"{self.doc.file_path}:{node.lineno}:{lhs_name}"
                df_node = DataflowNode(
                    id=target_id,
                    kind=DataflowNodeKind.ASSIGNMENT,
                    symbol=lhs_name,
                    location=loc,
                    function_name=self.current_function,
                )
                self.engine.nodes[target_id] = df_node
                self.engine.edges.append(
                    DataflowEdge(
                        source_id=rhs_id,
                        target_id=target_id,
                        edge_type=DataflowEdgeType.ASSIGNMENT,
                    )
                )
                self.var_node_map[lhs_name] = target_id

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        loc = ASTLocation(
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            column_start=node.col_offset,
            column_end=node.end_col_offset or node.col_offset,
        )

        # Check if source
        if any(call_name.startswith(src) or src in call_name for src in ["request.args", "request.GET", "request.POST", "request.json", "os.getenv", "input"]):
            src_id = f"source:{node.lineno}:{call_name}"
            src_node = DataflowNode(
                id=src_id,
                kind=DataflowNodeKind.SOURCE,
                symbol=call_name,
                location=loc,
                function_name=self.current_function,
                taint_state=TaintStateEnum.TAINTED,
                metadata={"category": TaintSourceCategory.HTTP_REQUEST.value},
            )
            self.engine.nodes[src_id] = src_node

        # Check if sink
        sink_cat = None
        if call_name in ("eval", "exec", "os.system", "subprocess.call", "subprocess.Popen", "os.popen"):
            sink_cat = TaintSinkCategory.COMMAND_INJECTION if "system" in call_name or "subprocess" in call_name else TaintSinkCategory.CODE_EXECUTION
        elif "execute" in call_name or "query" in call_name:
            sink_cat = TaintSinkCategory.SQL_INJECTION
        elif call_name in ("open", "pickle.loads", "yaml.load"):
            sink_cat = TaintSinkCategory.PATH_TRAVERSAL if call_name == "open" else TaintSinkCategory.CODE_EXECUTION

        if sink_cat:
            sink_id = f"sink:{node.lineno}:{call_name}"
            sink_node = DataflowNode(
                id=sink_id,
                kind=DataflowNodeKind.SINK,
                symbol=call_name,
                location=loc,
                function_name=self.current_function,
                metadata={"category": sink_cat.value},
            )
            self.engine.nodes[sink_id] = sink_node

            # Connect arguments to sink
            for arg in node.args:
                arg_id = self._process_expr(arg)
                if arg_id:
                    self.engine.edges.append(
                        DataflowEdge(
                            source_id=arg_id,
                            target_id=sink_id,
                            edge_type=DataflowEdgeType.PARAMETER,
                        )
                    )

        # Check if sanitizer
        if self.engine.sanitizer_registry.get_sanitizer(call_name):
            san_id = f"sanitizer:{node.lineno}:{call_name}"
            san_node = DataflowNode(
                id=san_id,
                kind=DataflowNodeKind.SANITIZATION,
                symbol=call_name,
                location=loc,
                function_name=self.current_function,
            )
            self.engine.nodes[san_id] = san_node
            for arg in node.args:
                arg_id = self._process_expr(arg)
                if arg_id:
                    self.engine.edges.append(
                        DataflowEdge(
                            source_id=arg_id,
                            target_id=san_id,
                            edge_type=DataflowEdgeType.SANITIZATION,
                        )
                    )

        # Connect interprocedural function calls
        for arg_idx, arg in enumerate(node.args):
            arg_id = self._process_expr(arg)
            if arg_id:
                param_id = f"{call_name}:param_{arg_idx}"
                if param_id not in self.engine.nodes:
                    self.engine.nodes[param_id] = DataflowNode(
                        id=param_id,
                        kind=DataflowNodeKind.PARAMETER,
                        symbol=f"arg_{arg_idx}",
                        function_name=call_name,
                    )
                self.engine.edges.append(
                    DataflowEdge(
                        source_id=arg_id,
                        target_id=param_id,
                        edge_type=DataflowEdgeType.CALL,
                    )
                )

        self.generic_visit(node)

    def _process_expr(self, expr: ast.AST) -> str | None:
        if isinstance(expr, ast.Name):
            return self.var_node_map.get(expr.id)
        elif isinstance(expr, ast.Attribute):
            name = self._get_name(expr)
            return self.var_node_map.get(name) or self.var_node_map.get(expr.attr)
        elif isinstance(expr, ast.Call):
            call_name = self._get_name(expr.func)
            if call_name and any(call_name.startswith(src) or src in call_name for src in ["request.args", "request.GET", "request.POST", "request.json", "os.getenv", "input"]):
                loc = ASTLocation(line_start=expr.lineno, line_end=expr.end_lineno or expr.lineno, column_start=expr.col_offset, column_end=expr.end_col_offset or expr.col_offset)
                src_id = f"source:{expr.lineno}:{call_name}"
                if src_id not in self.engine.nodes:
                    self.engine.nodes[src_id] = DataflowNode(
                        id=src_id,
                        kind=DataflowNodeKind.SOURCE,
                        symbol=call_name,
                        location=loc,
                        function_name=self.current_function,
                        taint_state=TaintStateEnum.TAINTED,
                        metadata={"category": TaintSourceCategory.HTTP_REQUEST.value},
                    )
                return src_id
            if call_name and self.engine.sanitizer_registry.get_sanitizer(call_name):
                san_id = f"sanitizer:{expr.lineno}:{call_name}"
                if san_id not in self.engine.nodes:
                    self.engine.nodes[san_id] = DataflowNode(
                        id=san_id,
                        kind=DataflowNodeKind.SANITIZATION,
                        symbol=call_name,
                        function_name=self.current_function,
                    )
                for arg in expr.args:
                    arg_id = self._process_expr(arg)
                    if arg_id:
                        self.engine.edges.append(
                            DataflowEdge(
                                source_id=arg_id,
                                target_id=san_id,
                                edge_type=DataflowEdgeType.SANITIZATION,
                            )
                        )
                return san_id
            # Process call args if any
            for arg in expr.args:
                res = self._process_expr(arg)
                if res:
                    return res
        elif isinstance(expr, ast.BinOp):
            left_res = self._process_expr(expr.left)
            if left_res:
                return left_res
            right_res = self._process_expr(expr.right)
            if right_res:
                return right_res
        elif isinstance(expr, ast.Subscript):
            return self._process_expr(expr.value)
        elif isinstance(expr, ast.JoinedStr):  # f-string
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    res = self._process_expr(value.value)
                    if res:
                        return res
        return None

    def _get_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        return ""
