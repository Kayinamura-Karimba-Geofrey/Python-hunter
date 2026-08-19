"""Abstract FrameworkAdapter interface."""

from abc import ABC, abstractmethod
from python_hunter.domain.frameworks.framework_models import ApplicationModel, FrameworkCapability
from python_hunter.domain.language.models import Language


class FrameworkAdapter(ABC):
    """Base interface for framework adapters (Django, Flask, FastAPI, Express, NestJS)."""

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Unique framework identifier."""
        pass

    @property
    @abstractmethod
    def language(self) -> Language:
        """Primary programming language of the framework."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> set[FrameworkCapability]:
        """Declared capabilities of the framework adapter."""
        pass

    @abstractmethod
    def detect_and_enrich(self, workspace_path: str) -> ApplicationModel | None:
        """Statically detect framework usage in workspace and build ApplicationModel."""
        pass
