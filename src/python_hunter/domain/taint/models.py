"""Taint Domain Data Models and Entities."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.ast.models import ASTLocation
from python_hunter.domain.common.enums import Category, Confidence, Severity


class TaintStateEnum(str, Enum):
    """Taint state classification of variables and expressions."""

    CLEAN = "CLEAN"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"
    MAYBE_TAINTED = "MAYBE_TAINTED"
    UNKNOWN = "UNKNOWN"


class SanitizationContext(str, Enum):
    """Safety domain context for sanitizers."""

    SQL_SAFE = "SQL_SAFE"
    SHELL_SAFE = "SHELL_SAFE"
    PATH_SAFE = "PATH_SAFE"
    HTML_SAFE = "HTML_SAFE"
    SSRF_SAFE = "SSRF_SAFE"
    GENERAL_SAFE = "GENERAL_SAFE"


class TaintSourceCategory(str, Enum):
    """Origin categories of untrusted taint data."""

    HTTP_REQUEST = "HTTP_REQUEST"
    CLI_ARGUMENT = "CLI_ARGUMENT"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    FILE_READ = "FILE_READ"
    DATABASE_DATA = "DATABASE_DATA"
    UNTRUSTED_EXTERNAL_DATA = "UNTRUSTED_EXTERNAL_DATA"


class TaintSinkCategory(str, Enum):
    """Target categories of security-sensitive operations."""

    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_EXECUTION = "CODE_EXECUTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    HTML_RESPONSE = "HTML_RESPONSE"

    @property
    def required_sanitization_context(self) -> SanitizationContext:
        """Map sink category to required safety context."""
        mapping = {
            TaintSinkCategory.SQL_INJECTION: SanitizationContext.SQL_SAFE,
            TaintSinkCategory.COMMAND_INJECTION: SanitizationContext.SHELL_SAFE,
            TaintSinkCategory.PATH_TRAVERSAL: SanitizationContext.PATH_SAFE,
            TaintSinkCategory.HTML_RESPONSE: SanitizationContext.HTML_SAFE,
            TaintSinkCategory.SSRF: SanitizationContext.SSRF_SAFE,
            TaintSinkCategory.CODE_EXECUTION: SanitizationContext.GENERAL_SAFE,
            TaintSinkCategory.TEMPLATE_INJECTION: SanitizationContext.GENERAL_SAFE,
        }
        return mapping.get(self, SanitizationContext.GENERAL_SAFE)


@dataclass
class TaintNode:
    """Graph node representing a variable or expression in a dataflow path."""

    label: str
    location: ASTLocation | None = None
    node_type: str = "variable"  # source, variable, assignment, call, sink
    description: str = ""

    def to_summary(self) -> str:
        loc_str = f" ({self.location.to_string()})" if self.location else ""
        return f"[{self.node_type.upper()}] {self.label}{loc_str}"


@dataclass
class TaintFlow:
    """Complete source-to-sink dataflow path."""

    source_node: TaintNode
    sink_node: TaintNode
    sink_category: TaintSinkCategory
    source_category: TaintSourceCategory
    flow_path: list[TaintNode] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)
    applied_sanitizers: list[tuple[str, SanitizationContext]] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    severity: Severity = Severity.HIGH
    vulnerability_type: str = "PYH-TAINT-001"

    @property
    def is_sanitized(self) -> bool:
        """Check if required safety context sanitizer was applied."""
        req_ctx = self.sink_category.required_sanitization_context
        return any(
            ctx == req_ctx or ctx == SanitizationContext.GENERAL_SAFE
            for _, ctx in self.applied_sanitizers
        )


@dataclass
class FunctionSummary:
    """Cached summary of function interprocedural taint flow."""

    function_name: str
    qualified_name: str
    parameter_names: list[str] = field(default_factory=list)
    # Param name -> indicates if parameter flows to return
    returns_param_taint: dict[str, bool] = field(default_factory=dict)
    # Param name -> list of (SinkCategory, TaintNode) reached internally
    internal_sinks: list[tuple[str, TaintSinkCategory, TaintNode]] = field(default_factory=list)
    # Sanitizations performed on parameters: param_name -> list of SanitizationContext
    sanitizations: dict[str, list[SanitizationContext]] = field(default_factory=dict)
