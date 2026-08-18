"""Abstract Base Framework Adapter Interface."""

from abc import ABC, abstractmethod
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.frameworks.models import (
    FrameworkEvidence,
    FrameworkProfile,
    FrameworkRoute,
    FrameworkType,
)
from python_hunter.domain.taint.models import TaintSinkCategory, TaintSourceCategory


class BaseFrameworkAdapter(ABC):
    """Abstract base class for framework-specific analysis adapters."""

    @property
    @abstractmethod
    def framework_type(self) -> FrameworkType:
        """Framework type identifier."""
        pass

    @abstractmethod
    def detect(self, documents: list[ASTDocument], dependencies: list[Any] | None = None) -> list[FrameworkEvidence]:
        """Detect evidence of framework presence in project AST documents."""
        pass

    @abstractmethod
    def discover_entry_points(self, documents: list[ASTDocument]) -> list[EntryPoint]:
        """Discover framework routes or task entry points."""
        pass

    @abstractmethod
    def discover_routes(self, documents: list[ASTDocument]) -> list[FrameworkRoute]:
        """Discover framework HTTP routes and handlers."""
        pass

    @abstractmethod
    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        """Register framework-specific input sources into taint configuration."""
        pass

    @abstractmethod
    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        """Register framework-specific security sinks into taint configuration."""
        pass

    @abstractmethod
    def analyze_framework_patterns(self, documents: list[ASTDocument], profile: FrameworkProfile) -> list[Finding]:
        """Execute framework-specific security pattern analysis (e.g. debug mode, secret keys)."""
        pass
