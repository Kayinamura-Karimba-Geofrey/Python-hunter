"""AST Domain Data Models and Structural Extracted Entities."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ASTLocation:
    """Source code location representation for AST nodes."""

    file_path: str
    line_start: int
    column_start: int
    line_end: int | None = None
    column_end: int | None = None

    def to_string(self) -> str:
        if self.line_end and self.line_end != self.line_start:
            return f"{self.file_path}:{self.line_start}-{self.line_end}"
        return f"{self.file_path}:{self.line_start}:{self.column_start}"


@dataclass(frozen=True)
class ImportInfo:
    """Discovered Python module import details."""

    module: str
    imported_name: str | None = None
    alias: str | None = None
    is_from_import: bool = False
    location: ASTLocation | None = None


@dataclass(frozen=True)
class CallInfo:
    """Discovered function/method call details."""

    name: str
    qualified_name: str
    resolved_alias: str | None = None
    arguments_count: int = 0
    keyword_arguments: dict[str, str] = field(default_factory=dict)
    location: ASTLocation | None = None


@dataclass(frozen=True)
class DecoratorInfo:
    """Discovered decorator details."""

    name: str
    arguments_count: int = 0
    location: ASTLocation | None = None


@dataclass(frozen=True)
class FunctionInfo:
    """Discovered function definition details."""

    name: str
    qualified_name: str
    is_async: bool = False
    arguments: list[str] = field(default_factory=list)
    decorators: list[DecoratorInfo] = field(default_factory=list)
    location: ASTLocation | None = None


@dataclass(frozen=True)
class ClassInfo:
    """Discovered class definition details."""

    name: str
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)
    decorators: list[DecoratorInfo] = field(default_factory=list)
    location: ASTLocation | None = None


@dataclass(frozen=True)
class AssignmentInfo:
    """Discovered variable assignment details."""

    target: str
    value_type: str
    location: ASTLocation | None = None


@dataclass(frozen=True)
class ASTParseError:
    """Parsing failure detail."""

    file_path: str
    error_type: str
    message: str
    line: int | None = None
    column: int | None = None


@dataclass
class ASTDocument:
    """AST Document representing parsed Python file structure."""

    file_path: str
    module_name: str
    source_lines: list[str] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    assignments: list[AssignmentInfo] = field(default_factory=list)
    decorators: list[DecoratorInfo] = field(default_factory=list)
    constants: list[str] = field(default_factory=list)
    parse_error: ASTParseError | None = None


@dataclass
class ASTAnalysisSummary:
    """Aggregate summary result across parsed AST documents."""

    files_analyzed: int = 0
    files_parsed: int = 0
    syntax_errors: int = 0
    total_imports: int = 0
    total_functions: int = 0
    total_classes: int = 0
    total_calls: int = 0
    total_assignments: int = 0
    total_decorators: int = 0
    documents: list[ASTDocument] = field(default_factory=list)
    errors: list[ASTParseError] = field(default_factory=list)
