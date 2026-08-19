"""Language Enum, AnalyzerCapability, and LanguageCapabilities models."""

from dataclasses import dataclass, field
from enum import Enum


class Language(str, Enum):
    """Supported programming language identifiers."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    CPP = "cpp"
    UNKNOWN = "unknown"


class AnalyzerCapability(str, Enum):
    """Capabilities supported by a language adapter."""

    AST = "AST"
    CFG = "CFG"
    CALL_GRAPH = "CALL_GRAPH"
    DATAFLOW = "DATAFLOW"
    TAINT = "TAINT"
    DEPENDENCY_ANALYSIS = "DEPENDENCY_ANALYSIS"
    FRAMEWORK_ANALYSIS = "FRAMEWORK_ANALYSIS"
    TYPE_ANALYSIS = "TYPE_ANALYSIS"


@dataclass
class LanguageCapabilities:
    """Set of capabilities supported by a language adapter."""

    capabilities: set[AnalyzerCapability] = field(default_factory=set)

    def supports(self, cap: AnalyzerCapability) -> bool:
        return cap in self.capabilities
