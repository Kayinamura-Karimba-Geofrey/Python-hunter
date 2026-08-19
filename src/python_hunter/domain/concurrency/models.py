"""Domain models and value objects for Concurrency and Asynchronous Security Analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.common.value_objects import Location


class ExecutionModel(str, Enum):
    """Concurrency execution model classification."""

    SYNCHRONOUS = "SYNCHRONOUS"
    ASYNC_TASK = "ASYNC_TASK"
    THREAD = "THREAD"
    PROCESS = "PROCESS"
    EXECUTOR = "EXECUTOR"
    BACKGROUND_WORKER = "BACKGROUND_WORKER"
    UNKNOWN = "UNKNOWN"


class StateClassification(str, Enum):
    """Scope classification for state access."""

    LOCAL = "LOCAL"
    TASK_LOCAL = "TASK_LOCAL"
    THREAD_LOCAL = "THREAD_LOCAL"
    PROCESS_LOCAL = "PROCESS_LOCAL"
    SHARED = "SHARED"
    EXTERNAL = "EXTERNAL"


@dataclass
class ConcurrencyContext:
    """Represents an execution context (coroutine, task, thread, process, worker)."""

    context_id: str
    execution_model: ExecutionModel
    name: str = ""
    parent_context_id: str | None = None
    file_path: str = ""
    location: Location | None = None
    shared_resources: list[str] = field(default_factory=list)
    synchronization_objects: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SharedResource:
    """Discovered shared mutable state resource."""

    name: str
    resource_type: str  # global, class_attr, module_attr, cache, db, file
    state_classification: StateClassification
    file_path: str
    location: Location | None = None
    accessed_by_contexts: list[str] = field(default_factory=list)
    is_synchronized: bool = False
    protecting_locks: list[str] = field(default_factory=list)


@dataclass
class SynchronizationObject:
    """Discovered synchronization object (Lock, RLock, Semaphore, Event, Condition, Queue)."""

    name: str
    sync_type: str  # Lock, RLock, Semaphore, Event, Condition, Queue
    execution_model: ExecutionModel
    file_path: str
    location: Location | None = None
    protected_resources: list[str] = field(default_factory=list)


@dataclass
class LockEdge:
    """Lock acquisition ordering edge (Lock A -> Lock B)."""

    from_lock: str
    to_lock: str
    file_path: str
    location: Location | None = None
    context_id: str = ""


@dataclass
class LockOrderGraph:
    """Directed graph representing lock acquisition order for deadlock analysis."""

    nodes: set[str] = field(default_factory=set)
    edges: list[LockEdge] = field(default_factory=list)

    def add_edge(self, from_lock: str, to_lock: str, file_path: str, location: Location | None = None, context_id: str = "") -> None:
        self.nodes.add(from_lock)
        self.nodes.add(to_lock)
        self.edges.append(LockEdge(from_lock, to_lock, file_path, location, context_id))

    def find_cycles(self) -> list[list[str]]:
        """Find deadlock cycles in the lock order graph using Tarjan / Depth-First Search."""
        adj: dict[str, list[str]] = {}
        for edge in self.edges:
            adj.setdefault(edge.from_lock, []).append(edge.to_lock)

        cycles = []
        visited = set()
        rec_stack = set()
        path = []

        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Cycle detected
                    idx = path.index(neighbor)
                    cycle = path[idx:] + [neighbor]
                    if cycle not in cycles:
                        cycles.append(cycle)

            path.pop()
            rec_stack.remove(node)

        for n in list(self.nodes):
            if n not in visited:
                dfs(n)

        return cycles


@dataclass
class RaceCandidate:
    """Candidate race condition (Write/Write, Read/Write, TOCTOU)."""

    resource_name: str
    race_type: str  # WRITE_WRITE, READ_WRITE, TOCTOU_FILE, TOCTOU_PERM, TOCTOU_DB
    writers: list[str] = field(default_factory=list)
    readers: list[str] = field(default_factory=list)
    execution_contexts: list[str] = field(default_factory=list)
    file_path: str = ""
    location: Location | None = None
    is_synchronized: bool = False
    is_security_sensitive: bool = False
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""


@dataclass
class ConcurrencySummary:
    """Statistical summary of concurrency analysis."""

    total_async_functions: int = 0
    total_await_points: int = 0
    total_tasks: int = 0
    total_threads: int = 0
    total_processes: int = 0
    total_shared_resources: int = 0
    total_synchronization_objects: int = 0
    total_race_candidates: int = 0
    total_deadlock_candidates: int = 0
    security_races_count: int = 0
