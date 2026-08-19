"""Universal Security Intermediate Representation (SecurityIR) models."""

from dataclasses import dataclass, field
from typing import Any
from python_hunter.domain.language.models import Language


@dataclass
class IRLocation:
    """Universal source location across programming languages."""

    file_path: str
    start_line: int
    start_column: int = 0
    end_line: int = 0
    end_column: int = 0


@dataclass
class IRSymbol:
    """Universal symbol abstraction."""

    name: str
    qualified_name: str
    symbol_type: str
    location: IRLocation | None = None


@dataclass
class IRFunction:
    """Universal function / method abstraction."""

    name: str
    qualified_name: str
    location: IRLocation | None = None
    parameters: list[str] = field(default_factory=list)


@dataclass
class IRCall:
    """Universal function call abstraction."""

    caller: str
    callee: str
    arguments: list[str] = field(default_factory=list)
    location: IRLocation | None = None


@dataclass
class IRDataFlowEdge:
    """Universal dataflow edge abstraction."""

    source: str
    target: str
    transformation: str = "direct"
    location: IRLocation | None = None


@dataclass
class SecurityIR:
    """Container for language-neutral security intermediate representation."""

    language: Language
    ir_version: str = "1.0.0"
    symbols: list[IRSymbol] = field(default_factory=list)
    functions: list[IRFunction] = field(default_factory=list)
    calls: list[IRCall] = field(default_factory=list)
    dataflow_edges: list[IRDataFlowEdge] = field(default_factory=list)
