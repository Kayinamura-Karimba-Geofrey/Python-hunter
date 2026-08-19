"""LanguageAdapter Abstract Base Class."""

from abc import ABC, abstractmethod
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.models import Language, LanguageCapabilities


class LanguageAdapter(ABC):
    """Abstract interface defining capabilities and parsing contracts for language adapters."""

    @property
    @abstractmethod
    def language(self) -> Language:
        pass

    @property
    @abstractmethod
    def capabilities(self) -> LanguageCapabilities:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def build_ir(self, workspace_path: str) -> SecurityIR:
        pass
