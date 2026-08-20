"""Language Enum, AnalyzerCapability, LanguageCapabilities, and LanguageMetadata models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set, Optional


class Language(str, Enum):
    """Supported programming language identifiers."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    PHP = "php"
    RUBY = "ruby"
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
    API_DISCOVERY = "API_DISCOVERY"
    SECURITY_CONFIG_ANALYSIS = "SECURITY_CONFIG_ANALYSIS"


@dataclass
class LanguageCapabilities:
    """Set of capabilities supported by a language adapter."""

    capabilities: Set[AnalyzerCapability] = field(default_factory=set)

    def supports(self, cap: AnalyzerCapability) -> bool:
        return cap in self.capabilities

    def to_dict(self) -> dict:
        return {cap.value: True for cap in self.capabilities}


@dataclass
class LanguageMetadata:
    """Detailed specification and metadata for a supported language."""

    language: Language
    display_name: str
    aliases: List[str]
    file_extensions: List[str]
    parser: str
    analyzer: str
    framework_adapters: List[str]
    dependency_ecosystem: str
    capabilities: LanguageCapabilities
    version: str = "1.0.0"
