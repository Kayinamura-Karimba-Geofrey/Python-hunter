"""Call Graph, Control-Flow Graph (CFG), and Symbol Table Analysis Engine."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument, ASTLocation
from python_hunter.domain.callgraph.models import (
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    CFGNodeType,
    CallEdge,
    CallEdgeType,
    CallSite,
    ControlFlowGraph,
    EntryPoint,
    EntryPointType,
    ImportEdge,
    ReachabilityResult,
    Symbol,
    SymbolType,
)
from python_hunter.domain.common.enums import Confidence


class CallGraphEngine:
    """Static Program-Analysis Engine for Symbol Tables, Import Graphs, Call Graphs, and CFGs."""

    def __init__(self) -> None:
        self.symbols: dict[str, Symbol] = {}  # qualified_name -> Symbol
        self.imports: list[ImportEdge] = []
        self.call_sites: list[CallSite] = []
        self.call_edges: list[CallEdge] = []
        self.entry_points: list[EntryPoint] = []
        self.cfgs: dict[str, ControlFlowGraph] = {}  # qualified_name -> CFG
        self.alias_map: dict[str, str] = {}  # local_name -> qualified_target

    def analyze_documents(self, documents: list[ASTDocument]) -> dict[str, Any]:
        """Analyze project AST documents to construct symbols, import graph, call graph, and CFGs."""
        self._reset()

        # Step 1: Index all symbols (modules, classes, functions)
        for doc in documents:
            self._index_symbols(doc)

        # Step 2: Resolve imports and populate alias map
        for doc in documents:
            self._resolve_imports(doc)

        # Step 3: Extract call sites and construct call edges
        for doc in documents:
            self._extract_call_sites(doc)

        # Step 4: Build CFGs for functions
        for doc in documents:
            self._build_cfgs(doc)

        # Step 5: Discover entry points
        for doc in documents:
            self._discover_entry_points(doc)

        # Step 6: Identify strongly connected components (cycles/recursion)
        sccs = self._find_strongly_connected_components()

        return {
            "symbols": self.symbols,
            "imports": self.imports,
            "call_sites": self.call_sites,
            "call_edges": self.call_edges,
            "entry_points": self.entry_points,
            "cfgs": self.cfgs,
            "sccs": sccs,
        }

    def _reset(self) -> None:
        self.symbols.clear()
        self.imports.clear()
        self.call_sites.clear()
        self.call_edges.clear()
        self.entry_points.clear()
        self.cfgs.clear()
        self.alias_map.clear()

    def _index_symbols(self, doc: ASTDocument) -> None:
        mod_sym = Symbol(
            name=doc.module_name,
            qualified_name=doc.module_name,
            symbol_type=SymbolType.MODULE,
            file_path=doc.file_path,
        )
        self.symbols[doc.module_name] = mod_sym

        for cls in doc.classes:
            cls_qname = f"{doc.module_name}.{cls.name}"
            cls_sym = Symbol(
                name=cls.name,
                qualified_name=cls_qname,
                symbol_type=SymbolType.CLASS,
                file_path=doc.file_path,
                location=cls.location,
            )
            self.symbols[cls_qname] = cls_sym

            for m in cls.methods:
                m_qname = f"{cls_qname}.{m.name}"
                is_static = any(d.name == "staticmethod" for d in m.decorators)
                is_cls = any(d.name == "classmethod" for d in m.decorators)
                stype = (
                    SymbolType.STATIC_METHOD
                    if is_static
                    else SymbolType.CLASS_METHOD
                    if is_cls
                    else SymbolType.METHOD
                )
                m_sym = Symbol(
                    name=m.name,
                    qualified_name=m_qname,
                    symbol_type=stype,
                    file_path=doc.file_path,
                    location=m.location,
                    parameters=m.arguments,
                    is_async=m.is_async,
                    decorators=[d.name for d in m.decorators],
                )
                self.symbols[m_qname] = m_sym

        for fn in doc.functions:
            fn_qname = f"{doc.module_name}.{fn.name}"
            fn_sym = Symbol(
                name=fn.name,
                qualified_name=fn_qname,
                symbol_type=SymbolType.FUNCTION,
                file_path=doc.file_path,
                location=fn.location,
                parameters=fn.arguments,
                is_async=fn.is_async,
                decorators=[d.name for d in fn.decorators],
            )
            self.symbols[fn_qname] = fn_sym

    def _resolve_imports(self, doc: ASTDocument) -> None:
        for imp in doc.imports:
            source = doc.module_name
            target = imp.module

            # Handle relative imports (e.g. from .utils import helper)
            if imp.module.startswith("."):
                parts = source.split(".")
                level = len(imp.module) - len(imp.module.lstrip("."))
                base_parts = parts[:-level] if level < len(parts) else []
                rel_mod = imp.module.lstrip(".")
                target = ".".join(base_parts + ([rel_mod] if rel_mod else []))

            imp_edge = ImportEdge(
                source_module=source,
                target_module=target,
                imported_symbol=imp.imported_name,
                alias=imp.alias,
                is_relative=imp.module.startswith("."),
                location=imp.location,
            )
            self.imports.append(imp_edge)

            # Record aliases for call resolution
            local_name = imp.alias or imp.imported_name or target.split(".")[-1]
            if imp.imported_name:
                resolved_qname = f"{target}.{imp.imported_name}"
            else:
                resolved_qname = target
            self.alias_map[f"{source}:{local_name}"] = resolved_qname

    def _extract_call_sites(self, doc: ASTDocument) -> None:
        for call in doc.calls:
            caller_qname = doc.module_name
            # If function name has dots, infer caller context or module
            callee_raw = call.name
            candidates = self._resolve_callee_candidates(doc.module_name, callee_raw)

            confidence = Confidence.HIGH if candidates else Confidence.LOW
            edge_type = CallEdgeType.DIRECT
            if any("." in c for c in candidates):
                edge_type = CallEdgeType.METHOD

            cs = CallSite(
                caller_qualified_name=caller_qname,
                callee_name=callee_raw,
                candidate_qualified_names=candidates,
                arguments_count=call.arguments_count,
                location=call.location,
                edge_type=edge_type,
                confidence=confidence,
            )
            self.call_sites.append(cs)

            for cand in candidates:
                edge = CallEdge(
                    caller_qualified_name=caller_qname,
                    callee_qualified_name=cand,
                    edge_type=edge_type,
                    confidence=confidence,
                    location=call.location,
                )
                self.call_edges.append(edge)

    def _resolve_callee_candidates(self, module_name: str, callee_raw: str) -> list[str]:
        # Check standard builtins
        builtins = {
            "print", "len", "range", "str", "int", "float", "list", "dict", "set",
            "tuple", "bool", "type", "isinstance", "issubclass", "open", "abs",
            "all", "any", "enumerate", "zip", "super", "getattr", "setattr", "hasattr"
        }
        if callee_raw in builtins:
            return [f"builtins.{callee_raw}"]

        # Check direct local module symbol
        local_qname = f"{module_name}.{callee_raw}"
        if local_qname in self.symbols:
            return [local_qname]

        # Check import alias map
        alias_key = f"{module_name}:{callee_raw.split('.')[0]}"
        if alias_key in self.alias_map:
            resolved_base = self.alias_map[alias_key]
            rest = ".".join(callee_raw.split(".")[1:])
            full_resolved = f"{resolved_base}.{rest}" if rest else resolved_base
            if full_resolved in self.symbols or not rest:
                return [full_resolved]

        # Check existing symbols by short suffix match
        matches = [q for q in self.symbols if q.endswith(f".{callee_raw}")]
        if matches:
            return matches

        return []

    def _build_cfgs(self, doc: ASTDocument) -> None:
        for fn in doc.functions:
            qname = f"{doc.module_name}.{fn.name}"
            cfg = ControlFlowGraph(function_qualified_name=qname)

            entry_node = CFGNode(node_id=0, node_type=CFGNodeType.ENTRY, label="ENTRY", location=fn.location)
            stmt_node = CFGNode(node_id=1, node_type=CFGNodeType.STATEMENT, label=f"Body of {fn.name}")
            exit_node = CFGNode(node_id=2, node_type=CFGNodeType.EXIT, label="EXIT")

            cfg.nodes[0] = entry_node
            cfg.nodes[1] = stmt_node
            cfg.nodes[2] = exit_node

            cfg.edges.append(CFGEdge(source_id=0, target_id=1, edge_type=CFGEdgeType.NORMAL))
            cfg.edges.append(CFGEdge(source_id=1, target_id=2, edge_type=CFGEdgeType.NORMAL))

            self.cfgs[qname] = cfg

    def _discover_entry_points(self, doc: ASTDocument) -> None:
        for fn in doc.functions:
            qname = f"{doc.module_name}.{fn.name}"
            for dec in fn.decorators:
                if any(kw in dec.name for kw in ["get", "post", "put", "delete", "route"]):
                    self.entry_points.append(
                        EntryPoint(
                            name=fn.name,
                            qualified_name=qname,
                            entry_type=EntryPointType.HTTP_ROUTE,
                            file_path=doc.file_path,
                            location=fn.location,
                            route_path="/" + fn.name,
                            http_method="GET",
                        )
                    )
                elif "command" in dec.name or "cli" in dec.name:
                    self.entry_points.append(
                        EntryPoint(
                            name=fn.name,
                            qualified_name=qname,
                            entry_type=EntryPointType.CLI_COMMAND,
                            file_path=doc.file_path,
                            location=fn.location,
                        )
                    )

        # Main block entry point discovery
        for const in doc.constants:
            if "__main__" in const:
                self.entry_points.append(
                    EntryPoint(
                        name="__main__",
                        qualified_name=f"{doc.module_name}.__main__",
                        entry_type=EntryPointType.MAIN_BLOCK,
                        file_path=doc.file_path,
                    )
                )

    def _find_strongly_connected_components(self) -> list[list[str]]:
        """Identify call graph cycles using Tarjan's SCC algorithm."""
        index = 0
        indices: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        sccs: list[list[str]] = []

        adj: dict[str, set[str]] = {}
        for edge in self.call_edges:
            adj.setdefault(edge.caller_qualified_name, set()).add(edge.callee_qualified_name)

        all_nodes = set(adj.keys()).union(*(adj.values()))

        def strongconnect(node: str) -> None:
            nonlocal index
            indices[node] = index
            lowlink[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)

            for neighbor in adj.get(node, []):
                if neighbor not in indices:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif neighbor in on_stack:
                    lowlink[node] = min(lowlink[node], indices[neighbor])

            if lowlink[node] == indices[node]:
                scc: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1 or (scc and scc[0] in adj.get(scc[0], set())):
                    sccs.append(scc)

        for node in all_nodes:
            if node not in indices:
                strongconnect(node)

        return sccs

    def compute_reachability(self, entry_point: EntryPoint, sink_name: str) -> ReachabilityResult:
        """Breadth-First Search (BFS) path reachability from entry point to target sink."""
        adj: dict[str, list[str]] = {}
        for edge in self.call_edges:
            adj.setdefault(edge.caller_qualified_name, []).append(edge.callee_qualified_name)

        start = entry_point.qualified_name
        queue: list[list[str]] = [[start]]
        visited: set[str] = {start}

        while queue:
            path = queue.pop(0)
            curr = path[-1]

            if sink_name in curr or curr.endswith(f".{sink_name}"):
                return ReachabilityResult(
                    entry_point=entry_point,
                    target_sink_name=sink_name,
                    call_path=path,
                    confidence=Confidence.HIGH,
                    is_reachable=True,
                )

            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return ReachabilityResult(
            entry_point=entry_point,
            target_sink_name=sink_name,
            call_path=[start],
            confidence=Confidence.LOW,
            is_reachable=False,
        )

    def export_dot(self) -> str:
        """Export call graph in Graphviz DOT format."""
        lines = ["digraph CallGraph {", "  rankdir=LR;", "  node [shape=box, fontname=Courier];"]
        for edge in self.call_edges:
            lines.append(f'  "{edge.caller_qualified_name}" -> "{edge.callee_qualified_name}";')
        lines.append("}")
        return "\n".join(lines)
