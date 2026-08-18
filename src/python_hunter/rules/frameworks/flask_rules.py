"""Flask Framework Security Rules."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule
from python_hunter.infrastructure.frameworks.flask_adapter import FlaskAdapter


class PYHFlask001Debug(SecurityRule):
    """Rule PYH-FLASK-001: Flask Debug Mode Enabled."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-FLASK-001",
            name="Flask Debug Mode Enabled in Application Code",
            description="app.run(debug=True) enables interactive debugger that permits arbitrary code execution if exposed.",
            category=Category.CONFIGURATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-489",
            owasp="A05:2021-Security Misconfiguration",
            remediation="Ensure debug=False in production deployments or control via environment variables.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        adapter = FlaskAdapter()
        profile = context.metadata.get("framework_profile") if context and hasattr(context, "metadata") else None
        return adapter.analyze_framework_patterns(ast_summary.documents, profile)


class PYHFlask002SecretKey(SecurityRule):
    """Rule PYH-FLASK-002: Hardcoded Flask Secret Key."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-FLASK-002",
            name="Hardcoded Flask Secret Key",
            description="Flask secret key is hardcoded in source code, enabling session forgery if exposed.",
            category=Category.SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            remediation="Load Flask secret_key securely from environment variables or secret manager.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        return []  # Evaluated by FlaskAdapter in PYHFlask001Debug call to prevent duplication
