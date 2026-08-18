"""Django Framework Security Rules."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule
from python_hunter.infrastructure.frameworks.django_adapter import DjangoAdapter


class PYHDjango001Debug(SecurityRule):
    """Rule PYH-DJANGO-001: Django Debug Mode Enabled."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DJANGO-001",
            name="Django Debug Mode Enabled",
            description="DEBUG = True in Django settings displays detailed tracebacks containing secrets and environment state on uncaught exceptions.",
            category=Category.CONFIGURATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-489",
            owasp="A05:2021-Security Misconfiguration",
            remediation="Set DEBUG = False in production settings or read dynamically from environment variables.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        adapter = DjangoAdapter()
        profile = context.metadata.get("framework_profile") if context and hasattr(context, "metadata") else None
        return adapter.analyze_framework_patterns(ast_summary.documents, profile)


class PYHDjango002CSRFExempt(SecurityRule):
    """Rule PYH-DJANGO-002: Explicit CSRF Protection Exemption."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DJANGO-002",
            name="Explicit CSRF Protection Exemption (@csrf_exempt)",
            description="View function explicitly disables CSRF protection using @csrf_exempt.",
            category=Category.CONFIGURATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-352",
            owasp="A01:2021-Broken Access Control",
            remediation="Ensure CSRF protection is enabled for state-changing HTTP endpoints.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        return []
