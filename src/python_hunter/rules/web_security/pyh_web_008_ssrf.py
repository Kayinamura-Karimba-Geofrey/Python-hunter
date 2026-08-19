"""PYH-WEB-008: Server-Side Request Forgery (SSRF) Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHWeb008SSRF(SecurityRule):
    """Detects Server-Side Request Forgery (SSRF) where external user input flows into HTTP client calls."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-WEB-008",
            name="Potential Server-Side Request Forgery (SSRF)",
            description="Outbound HTTP request target URL originates from untrusted user input without strict allowlist or IP validation.",
            category=Category.API_SECURITY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-918",
            owasp="A10:2021-Server-Side Request Forgery (SSRF)",
            remediation="Validate request targets using an explicit domain allowlist and block access to private/internal IP address spaces.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for doc in ast_summary.documents:
            for stmt in doc.statements:
                if any(client in stmt.code_snippet for client in ("requests.get(", "httpx.get(", "aiohttp.ClientSession")):
                    if any(arg in stmt.code_snippet for arg in ("url", "target_url", "dest_url")):
                        line = stmt.location.line_start if stmt.location else 1
                        loc = Location(line_start=line, line_end=line, column_start=stmt.location.column_start if stmt.location else 0)
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                confidence=self.confidence,
                                category=self.category,
                                title=self.name,
                                description="Outbound HTTP fetch call uses dynamic URL parameter.",
                                file_path=doc.file_path,
                                location=loc,
                                remediation=self.remediation,
                                risk_score=85.0,
                            )
                        )
        return findings
