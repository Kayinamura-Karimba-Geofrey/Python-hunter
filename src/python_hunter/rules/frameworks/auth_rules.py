"""Authentication & JWT Security Rules."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule
from python_hunter.infrastructure.frameworks.auth_adapter import AuthAdapter


class PYHJWT001VerifyDisabled(SecurityRule):
    """Rule PYH-JWT-001: Insecure JWT Signature Verification Disabled."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-JWT-001",
            name="Insecure JWT Signature Verification Disabled",
            description="jwt.decode call explicitly disables signature verification, allowing forged JWT tokens to be accepted.",
            category=Category.AUTHENTICATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe="CWE-347",
            owasp="A07:2021-Identification and Authentication Failures",
            remediation="Enforce signature verification when decoding JWT tokens.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        adapter = AuthAdapter()
        profile = context.metadata.get("framework_profile") if context and hasattr(context, "metadata") else None
        return adapter.analyze_framework_patterns(ast_summary.documents, profile)
