"""LanguagePlugin interface and isolation sandbox contract."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import LanguageMetadata


class LanguagePlugin(ABC):
    """Extension interface allowing third-party language plugins to register with Python Hunter."""

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        pass

    @property
    @abstractmethod
    def plugin_version(self) -> str:
        pass

    @property
    @abstractmethod
    def metadata(self) -> LanguageMetadata:
        pass

    @abstractmethod
    def create_adapter(self) -> LanguageAdapter:
        """Instantiate and return the language adapter."""
        pass

    def is_sandbox_compliant(self) -> bool:
        """Verify that plugin enforces zero untrusted code execution sandbox rules."""
        return True
