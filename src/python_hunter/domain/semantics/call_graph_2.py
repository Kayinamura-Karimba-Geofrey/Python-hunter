"""Call Graph 2.0 with dynamic dispatch, async flows, and callback tracking."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from python_hunter.domain.ir.models import IRLocation
from python_hunter.domain.semantics.program_model import ProgramCall, ProgramFunction, ProgramModel
from python_hunter.domain.semantics.symbol_table import NameResolver


class CallKind(str, Enum):
    DIRECT = "direct"
    METHOD = "method"
    INHERITED = "inherited"
    INTERFACE = "interface"
    CALLBACK = "callback"
    ASYNC = "async"
    FRAMEWORK_DISPATCH = "framework_dispatch"


@dataclass
class CallEdge:
    caller: str
    callee: str
    kind: CallKind
    is_conservative: bool = False
    possible_targets: List[str] = field(default_factory=list)
    location: Optional[IRLocation] = None


class CallGraph2:
    """Advanced Interprocedural Call Graph 2.0 supporting dynamic dispatch and async flows."""

    def __init__(self, program_model: ProgramModel, name_resolver: NameResolver) -> None:
        self.program_model = program_model
        self.name_resolver = name_resolver
        self.nodes: Set[str] = set()
        self.edges: List[CallEdge] = []
        self.adjacency: Dict[str, List[CallEdge]] = {}
        self.reverse_adjacency: Dict[str, List[CallEdge]] = {}

    def build(self) -> None:
        """Constructs Call Graph 2.0 from ProgramModel and resolved symbols."""
        for func in self.program_model.all_functions():
            self.nodes.add(func.qualified_name)

        for func in self.program_model.all_functions():
            for call in func.calls:
                targets = self.name_resolver.resolve_call(func, call.callee_name)
                is_conservative = len(targets) > 1

                kind = CallKind.DIRECT
                if call.is_async:
                    kind = CallKind.ASYNC
                elif call.is_callback:
                    kind = CallKind.CALLBACK
                elif call.framework_dispatched:
                    kind = CallKind.FRAMEWORK_DISPATCH
                elif func.class_name:
                    kind = CallKind.METHOD

                if not targets:
                    # External or unresolved target
                    target_name = call.callee_qualified_name or call.callee_name
                    self._add_edge(CallEdge(
                        caller=func.qualified_name,
                        callee=target_name,
                        kind=kind,
                        is_conservative=True,
                        possible_targets=[target_name],
                        location=call.location,
                    ))
                else:
                    for target in targets:
                        self._add_edge(CallEdge(
                            caller=func.qualified_name,
                            callee=target,
                            kind=kind,
                            is_conservative=is_conservative,
                            possible_targets=targets,
                            location=call.location,
                        ))

    def _add_edge(self, edge: CallEdge) -> None:
        self.nodes.add(edge.caller)
        self.nodes.add(edge.callee)
        self.edges.append(edge)
        self.adjacency.setdefault(edge.caller, []).append(edge)
        self.reverse_adjacency.setdefault(edge.callee, []).append(edge)

    def get_callees(self, caller: str) -> List[CallEdge]:
        return self.adjacency.get(caller, [])

    def get_callers(self, callee: str) -> List[CallEdge]:
        return self.reverse_adjacency.get(callee, [])

    def reachable_paths(self, source: str, target: str, max_depth: int = 10) -> List[List[str]]:
        """Finds all execution paths between source and target up to max_depth."""
        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth or current in path[:-1]:
                return
            if current == target:
                paths.append(list(path))
                return
            for edge in self.get_callees(current):
                dfs(edge.callee, path + [edge.callee], depth + 1)

        dfs(source, [source], 0)
        return paths


class CallbackAnalyzer:
    """Analyzes and registers event handlers, callbacks, and promise chains."""

    def __init__(self, call_graph: CallGraph2) -> None:
        self.call_graph = call_graph
        self.callbacks: Dict[str, List[str]] = {}  # trigger_event -> handler_functions

    def register_callback(self, trigger_event: str, handler_qualified_name: str) -> None:
        self.callbacks.setdefault(trigger_event, []).append(handler_qualified_name)
        # Inject call graph edge for framework callback dispatch
        self.call_graph._add_edge(CallEdge(
            caller=f"event:{trigger_event}",
            callee=handler_qualified_name,
            kind=CallKind.CALLBACK,
            is_conservative=False,
            possible_targets=[handler_qualified_name],
        ))


class AsyncFlowAnalyzer:
    """Handles async/await, promise chains, futures, goroutines, and event loop flows."""

    def __init__(self, call_graph: CallGraph2) -> None:
        self.call_graph = call_graph
        self.async_edges: List[CallEdge] = []

    def register_async_spawn(self, caller: str, async_func: str) -> None:
        edge = CallEdge(
            caller=caller,
            callee=async_func,
            kind=CallKind.ASYNC,
            is_conservative=False,
            possible_targets=[async_func],
        )
        self.async_edges.append(edge)
        self.call_graph._add_edge(edge)
