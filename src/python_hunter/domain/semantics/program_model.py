"""Unified ProgramModel abstraction representing code structures across files, services, and languages."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.ir.models import IRLocation
from python_hunter.domain.language.models import Language


class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    FIELD = "field"
    ENDPOINT = "endpoint"
    EXTERNAL_SYSTEM = "external_system"


@dataclass
class TypeInfo:
    """Type information with confidence rating."""
    type_name: str
    confidence: float = 1.0  # 0.0 to 1.0
    is_inferred: bool = False
    source: str = "static"  # static, inferred, framework


@dataclass
class ProgramVariable:
    name: str
    qualified_name: str
    type_info: Optional[TypeInfo] = None
    location: Optional[IRLocation] = None
    is_parameter: bool = False
    is_field: bool = False
    default_value: Optional[str] = None


@dataclass
class ProgramField:
    name: str
    qualified_name: str
    owner_class: str
    type_info: Optional[TypeInfo] = None
    location: Optional[IRLocation] = None


@dataclass
class ProgramCall:
    caller_qualified_name: str
    callee_name: str
    callee_qualified_name: Optional[str] = None
    possible_callees: List[str] = field(default_factory=list)  # Conservative dynamic dispatch
    arguments: List[str] = field(default_factory=list)
    location: Optional[IRLocation] = None
    is_async: bool = False
    is_callback: bool = False
    framework_dispatched: bool = False


@dataclass
class ProgramFunction:
    name: str
    qualified_name: str
    module_name: str
    class_name: Optional[str] = None
    parameters: List[ProgramVariable] = field(default_factory=list)
    return_type: Optional[TypeInfo] = None
    location: Optional[IRLocation] = None
    calls: List[ProgramCall] = field(default_factory=list)
    is_async: bool = False
    is_endpoint_handler: bool = False
    http_method: Optional[str] = None
    http_path: Optional[str] = None


@dataclass
class ProgramClass:
    name: str
    qualified_name: str
    module_name: str
    superclasses: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    fields: Dict[str, ProgramField] = field(default_factory=dict)
    methods: Dict[str, ProgramFunction] = field(default_factory=dict)
    location: Optional[IRLocation] = None


@dataclass
class ProgramModule:
    name: str
    file_path: str
    language: Language
    imports: List[str] = field(default_factory=list)
    imported_symbols: Dict[str, str] = field(default_factory=dict)  # local_alias -> target_qualified_name
    classes: Dict[str, ProgramClass] = field(default_factory=dict)
    functions: Dict[str, ProgramFunction] = field(default_factory=dict)
    variables: Dict[str, ProgramVariable] = field(default_factory=dict)


@dataclass
class EndpointNode:
    method: str
    path: str
    handler_qualified_name: str
    framework: str
    file_path: str


@dataclass
class ExternalSystemNode:
    system_type: str  # database, cache, message_queue, external_api
    connection_string: Optional[str] = None
    target_host: Optional[str] = None


class ProgramModel:
    """Central semantic model unifying modules, functions, classes, calls, dependencies, endpoints, and external systems."""

    def __init__(self) -> None:
        self.modules: Dict[str, ProgramModule] = {}
        self.endpoints: List[EndpointNode] = []
        self.external_systems: List[ExternalSystemNode] = []
        self.dependencies: Set[str] = set()

    def add_module(self, module: ProgramModule) -> None:
        self.modules[module.name] = module

    def get_function(self, qualified_name: str) -> Optional[ProgramFunction]:
        for mod in self.modules.values():
            if qualified_name in mod.functions:
                return mod.functions[qualified_name]
            for cls in mod.classes.values():
                if qualified_name in cls.methods:
                    return cls.methods[qualified_name]
        return None

    def get_class(self, qualified_name: str) -> Optional[ProgramClass]:
        for mod in self.modules.values():
            if qualified_name in mod.classes:
                return mod.classes[qualified_name]
        return None

    def all_functions(self) -> List[ProgramFunction]:
        funcs = []
        for mod in self.modules.values():
            funcs.extend(mod.functions.values())
            for cls in mod.classes.values():
                funcs.extend(cls.methods.values())
        return funcs
