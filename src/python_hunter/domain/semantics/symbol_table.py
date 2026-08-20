"""Language-independent SymbolTable and Scope-aware NameResolver."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.ir.models import IRLocation
from python_hunter.domain.semantics.program_model import (
    ProgramClass,
    ProgramFunction,
    ProgramModel,
    ProgramModule,
    ProgramVariable,
    SymbolKind,
    TypeInfo,
)


class ScopeKind(str, Enum):
    GLOBAL = "global"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    BLOCK = "block"


@dataclass
class Symbol:
    name: str
    qualified_name: str
    kind: SymbolKind
    scope_name: str
    type_info: Optional[TypeInfo] = None
    location: Optional[IRLocation] = None
    references: List[IRLocation] = field(default_factory=list)


class Scope:
    """Represents a lexical or logical scope in the program."""

    def __init__(self, name: str, kind: ScopeKind, parent: Optional["Scope"] = None) -> None:
        self.name = name
        self.kind = kind
        self.parent = parent
        self.symbols: Dict[str, Symbol] = {}

    def define(self, symbol: Symbol) -> None:
        self.symbols[symbol.name] = symbol

    def lookup(self, name: str, recursive: bool = True) -> Optional[Symbol]:
        if name in self.symbols:
            return self.symbols[name]
        if recursive and self.parent:
            return self.parent.lookup(name, recursive=True)
        return None


class SymbolTable:
    """Language-independent symbol table maintaining scope hierarchy."""

    def __init__(self) -> None:
        self.global_scope = Scope("global", ScopeKind.GLOBAL)
        self.scopes: Dict[str, Scope] = {"global": self.global_scope}

    def create_scope(self, name: str, kind: ScopeKind, parent_name: Optional[str] = "global") -> Scope:
        parent = self.scopes.get(parent_name, self.global_scope) if parent_name else None
        scope = Scope(name, kind, parent)
        self.scopes[name] = scope
        return scope

    def add_symbol(self, scope_name: str, symbol: Symbol) -> None:
        scope = self.scopes.get(scope_name)
        if not scope:
            scope = self.create_scope(scope_name, ScopeKind.MODULE)
        scope.define(symbol)

    def lookup_symbol(self, scope_name: str, name: str) -> Optional[Symbol]:
        scope = self.scopes.get(scope_name)
        if scope:
            return scope.lookup(name, recursive=True)
        return self.global_scope.lookup(name, recursive=True)


class NameResolver:
    """Resolves calls, methods, imports, and inherited methods conservatively."""

    def __init__(self, program_model: ProgramModel, symbol_table: SymbolTable) -> None:
        self.program_model = program_model
        self.symbol_table = symbol_table

    def resolve_call(self, caller_func: ProgramFunction, callee_name: str) -> List[str]:
        """Resolves a call name to candidate qualified function names.
        
        Returns a list of possible target qualified names. Preserves uncertainty if ambiguous.
        """
        targets: Set[str] = set()

        # 1. Check local module functions / imported symbols
        mod = self.program_model.modules.get(caller_func.module_name)
        if mod:
            if callee_name in mod.imported_symbols:
                targets.add(mod.imported_symbols[callee_name])
            
            local_qual = f"{mod.name}.{callee_name}"
            if local_qual in mod.functions:
                targets.add(local_qual)

        # 2. Check class methods and superclass inheritance if caller is inside a class
        if caller_func.class_name:
            class_qual = f"{caller_func.module_name}.{caller_func.class_name}"
            cls = self.program_model.get_class(class_qual)
            if cls:
                method_qual = f"{class_qual}.{callee_name}"
                if callee_name in cls.methods:
                    targets.add(method_qual)
                
                # Check inherited superclasses
                for super_name in cls.superclasses:
                    super_cls = self.program_model.get_class(super_name)
                    if super_cls and callee_name in super_cls.methods:
                        targets.add(f"{super_name}.{callee_name}")

        # 3. Global search fallback for functions with matching short name
        if not targets:
            for func in self.program_model.all_functions():
                if func.name == callee_name:
                    targets.add(func.qualified_name)

        return sorted(list(targets))
