"""Taint and Advanced Dataflow Domain Data Models and Entities."""

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
    VALIDATED = "VALIDATED"
    PARTIALLY_SANITIZED = "PARTIALLY_SANITIZED"
    MAYBE_TAINTED = "MAYBE_TAINTED"
    UNKNOWN = "UNKNOWN"


class TrustLevel(str, Enum):
    """Trust classification level of data sources."""

    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    AUTHENTICATED = "AUTHENTICATED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class ExploitabilityLevel(str, Enum):
    """Assessment level of path exploitability."""

    CONFIRMED = "CONFIRMED"
    HIGHLY_LIKELY = "HIGHLY_LIKELY"
    POTENTIAL = "POTENTIAL"
    UNLIKELY = "UNLIKELY"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
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


class DataflowNodeKind(str, Enum):
    """Classification of dataflow node roles."""

    SOURCE = "SOURCE"
    VARIABLE = "VARIABLE"
    ASSIGNMENT = "ASSIGNMENT"
    PARAMETER = "PARAMETER"
    RETURN = "RETURN"
    ATTRIBUTE = "ATTRIBUTE"
    CONTAINER = "CONTAINER"
    CALL = "CALL"
    TRANSFORMATION = "TRANSFORMATION"
    SANITIZATION = "SANITIZATION"
    VALIDATION = "VALIDATION"
    SINK = "SINK"


class DataflowEdgeType(str, Enum):
    """Propagation relationship edge types."""

    ASSIGNMENT = "ASSIGNMENT"
    PARAMETER = "PARAMETER"
    RETURN = "RETURN"
    ATTRIBUTE = "ATTRIBUTE"
    CONTAINER = "CONTAINER"
    CALL = "CALL"
    TRANSFORMATION = "TRANSFORMATION"
    SANITIZATION = "SANITIZATION"
    VALIDATION = "VALIDATION"
    EXCEPTION = "EXCEPTION"
    ALIAS = "ALIAS"
    UNPACKING = "UNPACKING"


@dataclass
class DataflowNode:
    """Rich Dataflow Graph Node entity."""

    id: str
    kind: DataflowNodeKind
    symbol: str
    location: ASTLocation | None = None
    scope: str = "global"
    function_name: str | None = None
    node_type: str = "unknown"
    taint_state: TaintStateEnum = TaintStateEnum.UNKNOWN
    confidence: Confidence = Confidence.HIGH
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataflowEdge:
    """Directed Dataflow Edge tracking flow relationships."""

    source_id: str
    target_id: str
    edge_type: DataflowEdgeType
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""


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
class ExploitabilityProof:
    """Complete, step-by-step security exploitability proof for a finding."""

    entry_point: str
    source_description: str
    source_category: TaintSourceCategory
    trust_level: TrustLevel
    sink_description: str
    sink_category: TaintSinkCategory
    transformations: list[str] = field(default_factory=list)
    validations: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    exploitability: ExploitabilityLevel = ExploitabilityLevel.POTENTIAL
    confidence: Confidence = Confidence.HIGH
    evidence_nodes: list[DataflowNode] = field(default_factory=list)

    def explain(self) -> str:
        """Generate human-readable detailed step-by-step evidence explanation."""
        lines = [
            f"=== Exploitability Proof for [{self.sink_category.value}] ===",
            f"Exploitability Assessment : {self.exploitability.value} (Confidence: {self.confidence.value})",
            f"Entry Point               : {self.entry_point}",
            f"Source ({self.source_category.value})  : {self.source_description} [Trust: {self.trust_level.value}]",
        ]
        if self.validations:
            lines.append(f"Validations Applied       : {', '.join(self.validations)}")
        if self.sanitizers:
            lines.append(f"Sanitizers Applied        : {', '.join(self.sanitizers)}")
        if self.transformations:
            lines.append(f"Transformations           : {', '.join(self.transformations)}")
        lines.append(f"Sink ({self.sink_category.value})    : {self.sink_description}")
        if self.preconditions:
            lines.append("Preconditions:")
            for cond in self.preconditions:
                lines.append(f"  • {cond}")
        return "\n".join(lines)


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
    proof: ExploitabilityProof | None = None

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


@dataclass
class SanitizerRule:
    """Rule defining a recognized sanitizing function."""

    name: str
    target_categories: list[TaintSinkCategory]
    sanitization_context: SanitizationContext
    is_full_sanitizer: bool = True
    confidence: Confidence = Confidence.HIGH


class SanitizerRegistry:
    """Registry mapping sanitizer functions to sink categories and contexts."""

    def __init__(self) -> None:
        self.rules: dict[str, SanitizerRule] = {}
        self._register_defaults()

    def register(self, rule: SanitizerRule) -> None:
        self.rules[rule.name] = rule

    def _register_defaults(self) -> None:
        # SQL
        self.register(SanitizerRule("cursor.execute", [TaintSinkCategory.SQL_INJECTION], SanitizationContext.SQL_SAFE))
        self.register(SanitizerRule("psycopg2.sql.Identifier", [TaintSinkCategory.SQL_INJECTION], SanitizationContext.SQL_SAFE))
        # Shell
        self.register(SanitizerRule("shlex.quote", [TaintSinkCategory.COMMAND_INJECTION], SanitizationContext.SHELL_SAFE))
        # Path
        self.register(SanitizerRule("os.path.abspath", [TaintSinkCategory.PATH_TRAVERSAL], SanitizationContext.PATH_SAFE, is_full_sanitizer=False))
        self.register(SanitizerRule("werkzeug.utils.secure_filename", [TaintSinkCategory.PATH_TRAVERSAL], SanitizationContext.PATH_SAFE))
        # HTML / XSS
        self.register(SanitizerRule("html.escape", [TaintSinkCategory.HTML_RESPONSE, TaintSinkCategory.TEMPLATE_INJECTION], SanitizationContext.HTML_SAFE))
        self.register(SanitizerRule("markupsafe.escape", [TaintSinkCategory.HTML_RESPONSE, TaintSinkCategory.TEMPLATE_INJECTION], SanitizationContext.HTML_SAFE))
        self.register(SanitizerRule("bleach.clean", [TaintSinkCategory.HTML_RESPONSE], SanitizationContext.HTML_SAFE))

    def get_sanitizer(self, name: str) -> SanitizerRule | None:
        return self.rules.get(name)


class ValidatorRegistry:
    """Registry for recognized validation patterns."""

    def __init__(self) -> None:
        self.validators: set[str] = {
            "isinstance",
            "type",
            "str.isdigit",
            "str.isalnum",
            "str.isnumeric",
            "re.fullmatch",
            "re.match",
        }

    def is_validator(self, name: str) -> bool:
        return name in self.validators
