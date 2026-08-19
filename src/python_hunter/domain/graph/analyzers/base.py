"""Base Graph Builder Interface."""

from abc import ABC, abstractmethod
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.graph.models import SecurityGraph


class BaseGraphBuilder(ABC):
    """Abstract base class for security knowledge graph builders."""

    @abstractmethod
    def build_graph(self, documents: list[ASTDocument], graph: SecurityGraph) -> None:
        """Populate graph with nodes and edges from AST documents."""
        pass
