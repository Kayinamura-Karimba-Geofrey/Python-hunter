"""Base Concurrency Analyzer Interface."""

import ast
from abc import ABC, abstractmethod
from typing import Any
from python_hunter.domain.ast.models import ASTDocument

from python_hunter.domain.concurrency.models import ConcurrencyContext, RaceCandidate, SynchronizationObject, SharedResource


class BaseConcurrencyAnalyzer(ABC):
    """Abstract base class for concurrency analyzers."""

    @abstractmethod
    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        """Analyze documents and return discovered concurrency entities."""
        pass
