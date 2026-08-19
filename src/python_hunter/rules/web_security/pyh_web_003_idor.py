"""PYH-WEB-003: Potential IDOR / BOLA Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHWeb003IDOR(SecurityRule):
    """Detects potential Insecure Direct Object Reference (IDOR) or Broken Object Level Authorization (BOLA)."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-WEB-003",
            name="Potential IDOR / BOLA Vulnerability",
            description="Route retrieves or updates resource targets by ID parameter without ownership verification or authorization check.",
            category=Category.API_SECURITY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-639",
            owasp="A01:2021-Broken Access Control",
            remediation="Enforce explicit resource ownership checks (e.g. filter_by(user_id=current_user.id)) before modifying or exposing object details.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for doc in ast_summary.documents:
            for stmt in doc.statements:
                if "/{id}" in stmt.code_snippet or "/{user_id}" in stmt.code_snippet:
                    if "user_id" not in stmt.code_snippet and "owner_id" not in stmt.code_snippet:
                        line = stmt.location.line_start if stmt.location else 1
                        loc = Location(line_start=line, line_end=line, column_start=stmt.location.column_start if stmt.location else 0)
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                confidence=self.confidence,
                                category=self.category,
                                title=self.name,
                                description="Endpoint contains ID parameter but lacks explicit resource ownership validation.",
                                file_path=doc.file_path,
                                location=loc,
                                remediation=self.remediation,
                                risk_score=80.0,
                            )
                        )
        return findings
