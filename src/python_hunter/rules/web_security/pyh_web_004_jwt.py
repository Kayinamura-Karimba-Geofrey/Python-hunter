"""PYH-WEB-004: JWT Validation Weakness Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHWeb004JWTWeakness(SecurityRule):
    """Detects JWT signature verification bypass or weak claim validation."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-WEB-004",
            name="JWT Signature Validation Bypass",
            description="JWT token decode call explicitly disables signature verification ('verify_signature': False).",
            category=Category.API_SECURITY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe="CWE-347",
            owasp="A02:2021-Cryptographic Failures",
            remediation="Always verify JWT signatures using trusted secrets or public keys.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for doc in ast_summary.documents:
            for stmt in doc.statements:
                if "jwt.decode" in stmt.code_snippet and "verify_signature" in stmt.code_snippet and "False" in stmt.code_snippet:
                    line = stmt.location.line_start if stmt.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=stmt.location.column_start if stmt.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=self.name,
                            description="JWT decoding disables signature verification.",
                            file_path=doc.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=95.0,
                        )
                    )
        return findings
