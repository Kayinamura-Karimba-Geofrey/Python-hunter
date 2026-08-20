"""LanguageAdapter Abstract Base Class for multi-language analysis."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.models import Language, LanguageCapabilities, LanguageMetadata


class LanguageAdapter(ABC):
    """Abstract interface defining capabilities and contracts for language adapters."""

    @property
    @abstractmethod
    def language(self) -> Language:
        pass

    @property
    @abstractmethod
    def metadata(self) -> LanguageMetadata:
        pass

    @property
    def capabilities(self) -> LanguageCapabilities:
        return self.metadata.capabilities

    @property
    def adapter_version(self) -> str:
        return self.metadata.version

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def detect(self, workspace_path: str) -> bool:
        """Detect if this language is present in the workspace."""
        pass

    @abstractmethod
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse source file into AST representation."""
        pass

    @abstractmethod
    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        """Run security rules analysis on target workspace for this language."""
        pass

    @abstractmethod
    def build_ir(self, workspace_path: str) -> SecurityIR:
        """Build Universal Security IR for this language."""
        pass

    def build_cfg(self, file_path: str) -> Optional[Any]:
        """Build Control Flow Graph for file if supported."""
        return None

    def build_call_graph(self, workspace_path: str) -> Optional[Any]:
        """Build Call Graph for workspace if supported."""
        return None

    def extract_symbols(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract functions, classes, and variable symbols."""
        return []

    def extract_imports(self, file_path: str) -> List[str]:
        """Extract imported packages / modules."""
        return []

    def extract_endpoints(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract HTTP/RPC API endpoint routes."""
        return []

    def extract_security_boundaries(self, workspace_path: str) -> List[Dict[str, Any]]:
        """Extract authentication/authorization security trust boundaries."""
        return []
