"""FastAPI Framework Security Rules."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule
from python_hunter.infrastructure.frameworks.fastapi_adapter import FastAPIAdapter


class PYHFastAPI001Auth(SecurityRule):
    """Rule PYH-FASTAPI-001: Unauthenticated Sensitive Route."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-FASTAPI-001",
            name="Unauthenticated Sensitive FastAPI Endpoint",
            description="Endpoint appears sensitive but lacks explicit authentication dependency (Depends(Security)).",
            category=Category.AUTHENTICATION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe="CWE-306",
            owasp="A01:2021-Broken Access Control",
            remediation="Add security dependencies (e.g. Depends(get_current_user)) to protect sensitive endpoints.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        adapter = FastAPIAdapter()
        profile = context.metadata.get("framework_profile") if context and hasattr(context, "metadata") else None
        return adapter.analyze_framework_patterns(ast_summary.documents, profile)
