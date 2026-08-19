"""Base Web Security Analyzer Interface."""

import ast
from abc import ABC, abstractmethod
from typing import Any
from python_hunter.domain.ast.models import ASTDocument


class BaseWebSecurityAnalyzer(ABC):
    """Abstract base class for web security analyzers."""

    @abstractmethod
    def analyze(self, documents: list[ASTDocument]) -> dict[str, Any]:
        """Analyze AST documents and return web security artifacts."""
        pass
