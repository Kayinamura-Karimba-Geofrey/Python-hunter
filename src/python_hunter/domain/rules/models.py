"""Security Rule Engine Domain Models and Contracts."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import time
from typing import Any

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding


@dataclass
class SecurityRule(ABC):
    """Abstract base class for all security rules."""

    id: str
    name: str
    description: str
    category: Category
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    owasp: str | None = None
    remediation: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @abstractmethod
    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        """Evaluate security rule logic against parsed AST summary and scan context."""


@dataclass
class RuleResult:
    """Execution result returned for a single evaluated security rule."""

    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error: str | None = None
