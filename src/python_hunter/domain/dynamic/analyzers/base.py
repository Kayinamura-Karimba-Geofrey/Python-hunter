"""Base class for dynamic analyzers."""

import ast
from abc import ABC, abstractmethod
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.dynamic.models import DynamicBehavior


class BaseDynamicAnalyzer(ABC):
    """Abstract interface for specialized dynamic Python behavior analyzers."""

    @abstractmethod
    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        """Analyze AST documents and extract dynamic behaviors."""
        pass
