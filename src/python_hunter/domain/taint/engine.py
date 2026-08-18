"""Static AST Dataflow & Taint Analysis Engine."""

import ast
import os
from typing import Any

from python_hunter.domain.ast.models import ASTDocument, ASTLocation
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.taint.config import TaintConfig
from python_hunter.domain.taint.models import (
    FunctionSummary,
    SanitizationContext,
    TaintFlow,
    TaintNode,
    TaintSinkCategory,
    TaintSourceCategory,
    TaintStateEnum,
)


class VariableTaintRecord:
    """Internal record tracking variable taint status and flow path."""

    def __init__(
        self,
        name: str,
        state: TaintStateEnum,
        source_category: TaintSourceCategory | None = None,
        source_node: TaintNode | None = None,
        path: list[TaintNode] | None = None,
        sanitizers: list[tuple[str, SanitizationContext]] | None = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> None:
        self.name = name
        self.state = state
        self.source_category = source_category or TaintSourceCategory.HTTP_REQUEST
        self.source_node = source_node or TaintNode(label=name, node_type="source")
        self.path = path or [self.source_node]
        self.sanitizers = sanitizers or []
        self.confidence = confidence


from python_hunter.domain.taint.advanced_engine import AdvancedDataflowEngine


class TaintAnalysisEngine:
    """Static AST dataflow analysis engine tracking taint propagation from sources to sinks."""

    def __init__(self, config: TaintConfig | None = None) -> None:
        self.config = config or TaintConfig()
        self.function_summaries: dict[str, FunctionSummary] = {}
        self.visited_functions: set[str] = set()
        self.advanced_engine = AdvancedDataflowEngine(config=self.config)

    def analyze_document(
        self, doc: ASTDocument, raw_ast: ast.AST | None = None
    ) -> list[TaintFlow]:
        """Analyze a parsed AST document and return discovered taint flows."""
        if raw_ast is None:
            try:
                raw_ast = ast.parse("\n".join(doc.source_lines))
            except Exception:
                return []

        visitor = ModuleTaintVisitor(
            file_path=doc.file_path,
            config=self.config,
            summaries=self.function_summaries,
            visited_functions=self.visited_functions,
        )
        visitor.visit(raw_ast)
        flows = list(visitor.discovered_flows)

        # Advanced Dataflow Engine integration
        adv_res = self.advanced_engine.analyze_documents([doc])
        adv_flows = adv_res.get("flows", [])
        
        # Attach proofs to existing flows or append new advanced flows
        for af in adv_flows:
            matched = False
            for f in flows:
                if f.sink_category == af.sink_category:
                    if not f.proof and af.proof:
                        f.proof = af.proof
                    matched = True
                    break
            if not matched:
                flows.append(af)

        return flows


class ModuleTaintVisitor(ast.NodeVisitor):
    """AST NodeVisitor executing intraprocedural and interprocedural taint propagation."""

    def __init__(
        self,
        file_path: str,
        config: TaintConfig,
        summaries: dict[str, FunctionSummary],
        visited_functions: set[str],
        call_depth: int = 0,
    ) -> None:
        self.file_path = file_path
        self.config = config
        self.summaries = summaries
        self.visited_functions = visited_functions
        self.call_depth = call_depth

        self.var_map: dict[str, VariableTaintRecord] = {}
        self.discovered_flows: list[TaintFlow] = []

    def _get_loc(self, node: ast.AST) -> ASTLocation:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        end_line = getattr(node, "end_lineno", line)
        end_col = getattr(node, "end_col_offset", col)
        return ASTLocation(
            file_path=self.file_path,
            line_start=line,
            column_start=col,
            line_end=end_line,
            column_end=end_col,
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        """Handle variable assignment: target = expression."""
        self.generic_visit(node)
        loc = self._get_loc(node)

        for target in node.targets:
            target_names = self._extract_target_names(target)
            expr_taint = self._evaluate_expression_taint(node.value)

            for t_name in target_names:
                if expr_taint and expr_taint.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                    new_node = TaintNode(
                        label=f"{t_name} = ...",
                        location=loc,
                        node_type="assignment",
                        description=f"Assigned value from tainted expression",
                    )
                    new_path = list(expr_taint.path) + [new_node]

                    self.var_map[t_name] = VariableTaintRecord(
                        name=t_name,
                        state=expr_taint.state,
                        source_category=expr_taint.source_category,
                        source_node=expr_taint.source_node,
                        path=new_path,
                        sanitizers=list(expr_taint.sanitizers),
                        confidence=expr_taint.confidence,
                    )
                elif expr_taint and expr_taint.state == TaintStateEnum.SANITIZED:
                    self.var_map[t_name] = VariableTaintRecord(
                        name=t_name,
                        state=TaintStateEnum.SANITIZED,
                        source_category=expr_taint.source_category,
                        source_node=expr_taint.source_node,
                        path=expr_taint.path,
                        sanitizers=list(expr_taint.sanitizers),
                        confidence=expr_taint.confidence,
                    )
                else:
                    # Clean assignment clears previous taint
                    if t_name in self.var_map:
                        self.var_map[t_name] = VariableTaintRecord(name=t_name, state=TaintStateEnum.CLEAN)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Handle annotated assignment: target: type = value."""
        if node.value:
            self.visit_Assign(ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno, col_offset=node.col_offset))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Handle augmented assignment: target += value."""
        self.generic_visit(node)
        loc = self._get_loc(node)
        target_names = self._extract_target_names(node.target)
        expr_taint = self._evaluate_expression_taint(node.value)

        for t_name in target_names:
            prev_rec = self.var_map.get(t_name)
            if (expr_taint and expr_taint.state == TaintStateEnum.TAINTED) or (prev_rec and prev_rec.state == TaintStateEnum.TAINTED):
                base_rec = expr_taint if (expr_taint and expr_taint.state == TaintStateEnum.TAINTED) else prev_rec
                if base_rec:
                    new_node = TaintNode(label=f"{t_name} += ...", location=loc, node_type="assignment")
                    self.var_map[t_name] = VariableTaintRecord(
                        name=t_name,
                        state=TaintStateEnum.TAINTED,
                        source_category=base_rec.source_category,
                        source_node=base_rec.source_node,
                        path=list(base_rec.path) + [new_node],
                        sanitizers=list(base_rec.sanitizers),
                        confidence=base_rec.confidence,
                    )

    def visit_Call(self, node: ast.Call) -> None:
        """Handle function / method call expression for sinks and sanitizers."""
        self.generic_visit(node)
        loc = self._get_loc(node)
        call_name = self._get_call_name(node.func)

        # 1. Check if call is a Sanitizer
        if call_name in self.config.sanitizers:
            san_ctx = self.config.sanitizers[call_name]
            for arg in node.args:
                arg_names = self._extract_target_names(arg)
                for a_name in arg_names:
                    rec = self.var_map.get(a_name)
                    if rec:
                        rec.sanitizers.append((call_name, san_ctx))
                        if rec.state == TaintStateEnum.TAINTED:
                            rec.state = TaintStateEnum.SANITIZED

        # 2. Check if call is a Dangerous Sink
        sink_cat = self._match_sink(call_name)
        if sink_cat:
            self._check_sink_call(node, call_name, sink_cat, loc)

    def visit_If(self, node: ast.If) -> None:
        """Handle conditional branches and mark maybe-tainted variables."""
        self.visit(node.test)
        initial_state = {k: v.state for k, v in self.var_map.items()}

        # Visit IF body
        for stmt in node.body:
            self.visit(stmt)
        if_state = {k: v.state for k, v in self.var_map.items()}

        # Reset state and visit ELSE body
        for k, rec in self.var_map.items():
            if k in initial_state:
                rec.state = initial_state[k]

        for stmt in node.orelse:
            self.visit(stmt)
        else_state = {k: v.state for k, v in self.var_map.items()}

        # Merge states
        all_keys = set(if_state.keys()) | set(else_state.keys())
        for k in all_keys:
            st_if = if_state.get(k, initial_state.get(k, TaintStateEnum.CLEAN))
            st_else = else_state.get(k, initial_state.get(k, TaintStateEnum.CLEAN))

            if st_if != st_else and (st_if == TaintStateEnum.TAINTED or st_else == TaintStateEnum.TAINTED):
                if k in self.var_map:
                    self.var_map[k].state = TaintStateEnum.MAYBE_TAINTED

    def visit_For(self, node: ast.For) -> None:
        """Handle loop iteration over tainted containers."""
        self.visit(node.iter)
        iter_taint = self._evaluate_expression_taint(node.iter)
        target_names = self._extract_target_names(node.target)
        loc = self._get_loc(node)

        if iter_taint and iter_taint.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
            for t_name in target_names:
                new_node = TaintNode(label=f"for {t_name} in container", location=loc, node_type="variable")
                self.var_map[t_name] = VariableTaintRecord(
                    name=t_name,
                    state=iter_taint.state,
                    source_category=iter_taint.source_category,
                    source_node=iter_taint.source_node,
                    path=list(iter_taint.path) + [new_node],
                    sanitizers=list(iter_taint.sanitizers),
                    confidence=iter_taint.confidence,
                )

        # Run loop body twice (fixed-point approximation)
        for _ in range(2):
            for stmt in node.body:
                self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definition and construct FunctionSummary."""
        func_name = node.name
        if func_name in self.visited_functions or self.call_depth > self.config.max_call_depth:
            return

        self.visited_functions.add(func_name)
        params = [arg.arg for arg in node.args.args]

        # Interprocedural analysis on function body with synthetic tainted parameter
        for param in params:
            sub_visitor = ModuleTaintVisitor(
                file_path=self.file_path,
                config=self.config,
                summaries=self.summaries,
                visited_functions=self.visited_functions,
                call_depth=self.call_depth + 1,
            )
            # Inject synthetic taint for parameter
            param_node = TaintNode(label=f"param {param}", node_type="source")
            sub_visitor.var_map[param] = VariableTaintRecord(
                name=param,
                state=TaintStateEnum.TAINTED,
                source_category=TaintSourceCategory.HTTP_REQUEST,
                source_node=param_node,
            )

            for stmt in node.body:
                sub_visitor.visit(stmt)

            # Check if internal sinks were reached
            summary = self.summaries.get(func_name) or FunctionSummary(function_name=func_name, qualified_name=func_name, parameter_names=params)
            for flow in sub_visitor.discovered_flows:
                summary.internal_sinks.append((param, flow.sink_category, flow.sink_node))

            self.summaries[func_name] = summary

        # Continue top-level visitor
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Support async function definition transparently."""
        func_def = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            lineno=node.lineno,
            col_offset=node.col_offset,
        )
        self.visit_FunctionDef(func_def)

    # --- Helper Methods ---

    def _extract_target_names(self, node: ast.AST) -> list[str]:
        """Extract variable names from assignment targets or subscript expressions."""
        if isinstance(node, ast.Name):
            return [node.id]
        elif isinstance(node, ast.Attribute):
            return [f"{self._get_call_name(node.value)}.{node.attr}"]
        elif isinstance(node, ast.Subscript):
            base = self._get_call_name(node.value)
            return [base]
        elif isinstance(node, (ast.Tuple, ast.List)):
            names = []
            for elt in node.elts:
                names.extend(self._extract_target_names(elt))
            return names
        return []

    def _get_call_name(self, node: ast.AST) -> str:
        """Extract string representation of call/attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_str = self._get_call_name(node.value)
            return f"{val_str}.{node.attr}" if val_str else node.attr
        elif isinstance(node, ast.Subscript):
            return self._get_call_name(node.value)
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""

    def _evaluate_expression_taint(self, node: ast.AST) -> VariableTaintRecord | None:
        """Evaluate if an AST expression references or evaluates to a tainted value."""
        if node is None:
            return None

        # 1. Direct variable reference
        if isinstance(node, ast.Name):
            rec = self.var_map.get(node.id)
            if rec:
                return rec
            # Direct source check (e.g. sys.argv)
            if node.id in self.config.sources:
                cat = self.config.sources[node.id]
                loc = self._get_loc(node)
                src_node = TaintNode(label=node.id, location=loc, node_type="source")
                return VariableTaintRecord(name=node.id, state=TaintStateEnum.TAINTED, source_category=cat, source_node=src_node)

        # 2. Attribute / Subscript reference (e.g. request.args["username"], os.environ.get("X"))
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            full_name = self._get_call_name(node)
            if full_name in self.var_map:
                return self.var_map[full_name]

            # Check matching prefix in config sources
            for src_pattern, cat in self.config.sources.items():
                if full_name.startswith(src_pattern) or src_pattern in full_name:
                    loc = self._get_loc(node)
                    src_node = TaintNode(label=full_name, location=loc, node_type="source")
                    return VariableTaintRecord(name=full_name, state=TaintStateEnum.TAINTED, source_category=cat, source_node=src_node)

        # 3. Binary Operation (e.g. "SELECT..." + username)
        elif isinstance(node, ast.BinOp):
            left_t = self._evaluate_expression_taint(node.left)
            right_t = self._evaluate_expression_taint(node.right)
            return left_t or right_t

        # 4. F-String (e.g. f"SELECT * FROM users WHERE name = {username}")
        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._evaluate_expression_taint(val.value)
                    if t and t.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                        return t

        # 5. Call return or format call (e.g. "SELECT {}".format(username))
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)

            # Check if source call (e.g. input(), os.getenv("X"), request.args.get("X"))
            for src_pattern, cat in self.config.sources.items():
                if call_name == src_pattern or call_name.startswith(src_pattern):
                    loc = self._get_loc(node)
                    src_node = TaintNode(label=f"{call_name}()", location=loc, node_type="source")
                    return VariableTaintRecord(name=call_name, state=TaintStateEnum.TAINTED, source_category=cat, source_node=src_node)

            # Check args passed to format/join or function
            for arg in node.args:
                t = self._evaluate_expression_taint(arg)
                if t and t.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                    return t

        # 6. Container literals ([a, b], {k: v})
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t = self._evaluate_expression_taint(elt)
                if t and t.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                    return t
        elif isinstance(node, ast.Dict):
            for v in node.values:
                t = self._evaluate_expression_taint(v)
                if t and t.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                    return t

        return None

    def _match_sink(self, call_name: str) -> TaintSinkCategory | None:
        """Match call name to configured dangerous sink category."""
        for pattern, cat in self.config.sinks.items():
            if call_name == pattern or call_name.endswith(f".{pattern}"):
                return cat
        return None

    def _check_sink_call(
        self, node: ast.Call, call_name: str, sink_cat: TaintSinkCategory, loc: ASTLocation
    ) -> None:
        """Inspect call arguments for tainted data flowing into dangerous sinks."""
        # 1. Parameterized SQL check: cursor.execute("SELECT ...", (params,))
        if sink_cat == TaintSinkCategory.SQL_INJECTION and len(node.args) >= 2:
            first_arg = node.args[0]
            # If 1st argument is a string literal (Constant or Str), SQL interpolation is avoided
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return
            elif isinstance(first_arg, ast.Str):
                return

        # 2. Command array check: subprocess.run(["ls", user_input]) without shell=True
        if sink_cat == TaintSinkCategory.COMMAND_INJECTION:
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True

            if len(node.args) >= 1 and isinstance(node.args[0], (ast.List, ast.Tuple)) and not has_shell_true:
                return

        # Evaluate arguments for taint flow
        for idx, arg in enumerate(node.args, start=1):
            expr_taint = self._evaluate_expression_taint(arg)
            if expr_taint and expr_taint.state in (TaintStateEnum.TAINTED, TaintStateEnum.MAYBE_TAINTED):
                sink_node = TaintNode(
                    label=f"{call_name}(arg#{idx})",
                    location=loc,
                    node_type="sink",
                    description=f"Data reached dangerous sink {call_name}",
                )
                full_path = list(expr_taint.path) + [sink_node]

                # Map sink category to vulnerability rule ID
                rule_mapping = {
                    TaintSinkCategory.SQL_INJECTION: "PYH-TAINT-SQL-001",
                    TaintSinkCategory.COMMAND_INJECTION: "PYH-TAINT-CMD-001",
                    TaintSinkCategory.PATH_TRAVERSAL: "PYH-TAINT-PATH-001",
                    TaintSinkCategory.SSRF: "PYH-TAINT-SSRF-001",
                    TaintSinkCategory.CODE_EXECUTION: "PYH-TAINT-CODE-001",
                    TaintSinkCategory.TEMPLATE_INJECTION: "PYH-TAINT-TEMPLATE-001",
                }
                vuln_id = rule_mapping.get(sink_cat, "PYH-TAINT-001")

                severity = Severity.CRITICAL if sink_cat in (TaintSinkCategory.COMMAND_INJECTION, TaintSinkCategory.CODE_EXECUTION) else Severity.HIGH

                flow = TaintFlow(
                    source_node=expr_taint.source_node,
                    sink_node=sink_node,
                    sink_category=sink_cat,
                    source_category=expr_taint.source_category,
                    flow_path=full_path,
                    applied_sanitizers=list(expr_taint.sanitizers),
                    confidence=expr_taint.confidence,
                    severity=severity,
                    vulnerability_type=vuln_id,
                )

                # Skip if properly sanitized for this specific sink
                if not flow.is_sanitized:
                    self.discovered_flows.append(flow)
