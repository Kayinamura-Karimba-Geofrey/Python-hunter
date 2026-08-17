"""AST Domain Interfaces and Abstract Base Classes."""

from abc import ABC, abstractmethod
import ast
from python_hunter.domain.ast.models import ASTDocument


class ASTSourceLoader(ABC):
    """Abstract interface for safely loading source code."""

    @abstractmethod
    def load_source(self, file_path: str, max_bytes: int = 2_000_000) -> tuple[str, list[str]]:
        """Safely load source content and lines."""


class ASTParserEngine(ABC):
    """Abstract interface for parsing Python source into ASTDocument."""

    @abstractmethod
    def parse_file(self, file_path: str, root_path: str = "") -> ASTDocument:
        """Parse source file into ASTDocument."""


class ASTVisitorInterface(ABC):
    """Abstract interface for AST Node Visitor."""

    @abstractmethod
    def visit_tree(self, tree: ast.AST, file_path: str, source_lines: list[str]) -> ASTDocument:
        """Traverse AST tree and construct ASTDocument."""
