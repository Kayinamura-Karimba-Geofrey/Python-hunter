"""Domain Data Models for Call Graph, Control-Flow Graph (CFG), and Symbol Table."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.ast.models import ASTLocation
from python_hunter.domain.common.enums import Confidence, Severity


class SymbolType(str, Enum):
    """Classification of indexed Python code symbols."""

    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    STATIC_METHOD = "STATIC_METHOD"
    CLASS_METHOD = "CLASS_METHOD"
    PROPERTY = "PROPERTY"
    VARIABLE = "VARIABLE"


class CallEdgeType(str, Enum):
    """Call site invocation relationship type."""

    DIRECT = "DIRECT"
    METHOD = "METHOD"
    CONSTRUCTOR = "CONSTRUCTOR"
    ASYNC = "ASYNC"
    DECORATED = "DECORATED"
    DYNAMIC = "DYNAMIC"
    UNKNOWN = "UNKNOWN"


class CFGNodeType(str, Enum):
    """Control-Flow Graph node classification."""

    ENTRY = "ENTRY"
    EXIT = "EXIT"
    STATEMENT = "STATEMENT"
    CONDITION = "CONDITION"
    LOOP = "LOOP"
    RETURN = "RETURN"
    RAISE = "RAISE"
    EXCEPTION = "EXCEPTION"


class CFGEdgeType(str, Enum):
    """Control-Flow Graph edge transition classification."""

    NORMAL = "NORMAL"
    TRUE = "TRUE"
    FALSE = "FALSE"
    LOOP = "LOOP"
    EXCEPTION = "EXCEPTION"
    RETURN = "RETURN"


class EntryPointType(str, Enum):
    """Application entry point classification."""

    HTTP_ROUTE = "HTTP_ROUTE"
    CLI_COMMAND = "CLI_COMMAND"
    BACKGROUND_TASK = "BACKGROUND_TASK"
    MAIN_BLOCK = "MAIN_BLOCK"


@dataclass
class Symbol:
    """Indexed Python program symbol with qualified identity."""

    name: str
    qualified_name: str
    symbol_type: SymbolType
    file_path: str
    location: ASTLocation | None = None
    parameters: list[str] = field(default_factory=list)
    is_async: bool = False
    decorators: list[str] = field(default_factory=list)


@dataclass
class ImportEdge:
    """Module-level import dependency relationship."""

    source_module: str
    target_module: str
    imported_symbol: str | None = None
    alias: str | None = None
    is_relative: bool = False
    location: ASTLocation | None = None
    confidence: Confidence = Confidence.HIGH


@dataclass
class CallSite:
    """Function or method call invocation site."""

    caller_qualified_name: str
    callee_name: str
    candidate_qualified_names: list[str] = field(default_factory=list)
    receiver: str | None = None
    arguments_count: int = 0
    location: ASTLocation | None = None
    edge_type: CallEdgeType = CallEdgeType.DIRECT
    confidence: Confidence = Confidence.HIGH


@dataclass
class CallEdge:
    """Interprocedural call edge between caller and callee symbols."""

    caller_qualified_name: str
    callee_qualified_name: str
    edge_type: CallEdgeType = CallEdgeType.DIRECT
    confidence: Confidence = Confidence.HIGH
    location: ASTLocation | None = None


@dataclass
class CFGNode:
    """Intraprocedural Control-Flow Graph node."""

    node_id: int
    node_type: CFGNodeType
    label: str
    location: ASTLocation | None = None
    statements: list[str] = field(default_factory=list)


@dataclass
class CFGEdge:
    """Control-Flow Graph edge transition between CFG nodes."""

    source_id: int
    target_id: int
    edge_type: CFGEdgeType = CFGEdgeType.NORMAL
    label: str = ""


@dataclass
class ControlFlowGraph:
    """Function-level intraprocedural Control-Flow Graph."""

    function_qualified_name: str
    nodes: dict[int, CFGNode] = field(default_factory=dict)
    edges: list[CFGEdge] = field(default_factory=list)
    entry_node_id: int = 0
    exit_node_id: int = 1


@dataclass
class EntryPoint:
    """Discovered application execution entry point."""

    name: str
    qualified_name: str
    entry_type: EntryPointType
    file_path: str
    location: ASTLocation | None = None
    route_path: str | None = None
    http_method: str | None = None


@dataclass
class ReachabilityResult:
    """Path reachability from application entry point to security sink."""

    entry_point: EntryPoint
    target_sink_name: str
    call_path: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    is_reachable: bool = True
