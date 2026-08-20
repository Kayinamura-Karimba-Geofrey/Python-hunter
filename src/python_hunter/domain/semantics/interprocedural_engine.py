"""Interprocedural Taint & Dataflow Analysis Engine."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from python_hunter.domain.ir.models import IRLocation
from python_hunter.domain.semantics.call_graph_2 import CallGraph2
from python_hunter.domain.semantics.program_model import ProgramFunction, ProgramModel
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


@dataclass
class FlowStep:
    location: Optional[IRLocation]
    description: str
    expression: str
    function_name: str
    file_path: str


@dataclass
class TaintFlowEvidence:
    source: TaintSourceDef
    sink: TaintSinkDef
    steps: List[FlowStep] = field(default_factory=list)
    sanitizers_applied: List[SanitizerDef] = field(default_factory=list)
    is_sanitized: bool = False
    confidence: float = 0.9


@dataclass
class DataflowNode:
    id: str
    label: str
    file_path: str
    line_number: int
    is_source: bool = False
    is_sink: bool = False


@dataclass
class DataflowEdge:
    source_id: str
    target_id: str
    transformation: str = "assign"


class DataflowGraph:
    """Reusable Dataflow Graph representing source-to-sink propagations."""

    def __init__(self) -> None:
        self.nodes: Dict[str, DataflowNode] = {}
        self.edges: List[DataflowEdge] = []

    def add_node(self, node: DataflowNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str, transformation: str = "assign") -> None:
        self.edges.append(DataflowEdge(source_id, target_id, transformation))


class InterproceduralEngine:
    """Performs interprocedural taint analysis across functions, files, modules, and services."""

    def __init__(
        self,
        program_model: ProgramModel,
        call_graph: CallGraph2,
        source_registry: TaintSourceRegistry,
        sink_registry: TaintSinkRegistry,
        sanitizer_registry: SanitizerRegistry,
    ) -> None:
        self.program_model = program_model
        self.call_graph = call_graph
        self.source_registry = source_registry
        self.sink_registry = sink_registry
        self.sanitizer_registry = sanitizer_registry

    def analyze_workspace(self) -> List[TaintFlowEvidence]:
        """Scans workspace for interprocedural taint flows from sources to sinks."""
        evidence_list: List[TaintFlowEvidence] = []
        all_funcs = self.program_model.all_functions()

        for func in all_funcs:
            # Check if function contains a source or acts as an HTTP handler receiving untrusted input
            sources = self._find_function_sources(func)
            if not sources:
                continue

            for src in sources:
                # Perform interprocedural DFS reachability to sinks
                visited_funcs: Set[str] = set()
                initial_steps = [FlowStep(
                    location=func.location,
                    description=f"Source [{src.name}] received in {func.name}",
                    expression=src.pattern,
                    function_name=func.qualified_name,
                    file_path=func.location.file_path if func.location else "",
                )]
                self._propagate_taint(
                    current_func=func,
                    current_src=src,
                    current_steps=initial_steps,
                    sanitizers_seen=[],
                    visited=visited_funcs,
                    results=evidence_list,
                    depth=0,
                    max_depth=8,
                )

        return evidence_list

    def _find_function_sources(self, func: ProgramFunction) -> List[TaintSourceDef]:
        sources: List[TaintSourceDef] = []
        # Endpoint handlers implicitly receive HTTP input
        if func.is_endpoint_handler:
            sources.append(TaintSourceDef(
                name="http_endpoint_input",
                category=SourceCategory.HTTP_INPUT,
                pattern=f"{func.http_method or 'GET'} {func.http_path or '/'} parameter",
                description="Endpoint handler input parameter",
            ))

        # Check call expressions or variables inside function
        for call in func.calls:
            matched = self.source_registry.matches(call.callee_name)
            sources.extend(matched)

        return sources

    def _propagate_taint(
        self,
        current_func: ProgramFunction,
        current_src: TaintSourceDef,
        current_steps: List[FlowStep],
        sanitizers_seen: List[SanitizerDef],
        visited: Set[str],
        results: List[TaintFlowEvidence],
        depth: int,
        max_depth: int,
    ) -> None:
        if depth > max_depth or current_func.qualified_name in visited:
            return
        visited.add(current_func.qualified_name)

        # 1. Check for sanitizers in current function calls
        current_sanitizers = list(sanitizers_seen)
        for call in current_func.calls:
            matched_sans = self.sanitizer_registry.matches(call.callee_name)
            current_sanitizers.extend(matched_sans)

        # 2. Check if current function calls any sinks
        for call in current_func.calls:
            matched_sinks = self.sink_registry.matches(call.callee_name)
            for snk in matched_sinks:
                # Check for sanitizers applied along the path
                effective_sanitizer = any(
                    SanitizerContext.is_sanitizer_effective(san, snk.category)
                    for san in current_sanitizers
                )

                step = FlowStep(
                    location=call.location,
                    description=f"Flow reached sink [{snk.name}] in {current_func.name}",
                    expression=call.callee_name,
                    function_name=current_func.qualified_name,
                    file_path=call.location.file_path if call.location else "",
                )

                evidence = TaintFlowEvidence(
                    source=current_src,
                    sink=snk,
                    steps=current_steps + [step],
                    sanitizers_applied=list(current_sanitizers),
                    is_sanitized=effective_sanitizer,
                    confidence=0.95 if not effective_sanitizer else 0.2,
                )
                results.append(evidence)

        # 3. Propagate to outgoing call targets (interprocedural)
        callee_edges = self.call_graph.get_callees(current_func.qualified_name)
        for edge in callee_edges:
            target_func = self.program_model.get_function(edge.callee)
            if target_func:
                step = FlowStep(
                    location=edge.location,
                    description=f"Calling function {target_func.name}",
                    expression=edge.callee,
                    function_name=target_func.qualified_name,
                    file_path=target_func.location.file_path if target_func.location else "",
                )
                self._propagate_taint(
                    current_func=target_func,
                    current_src=current_src,
                    current_steps=current_steps + [step],
                    sanitizers_seen=list(sanitizers_seen),
                    visited=set(visited),
                    results=results,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
