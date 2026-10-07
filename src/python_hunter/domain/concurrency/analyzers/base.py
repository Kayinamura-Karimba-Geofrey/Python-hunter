"""Base Concurrency Analyzer Interface."""

from abc import ABC, abstractmethod
from typing import Any
from python_hunter.domain.ast.models import ASTDocument



class BaseConcurrencyAnalyzer(ABC):
    """Abstract base class for concurrency analyzers."""

    @abstractmethod
    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        """Analyze documents and return discovered concurrency entities."""
