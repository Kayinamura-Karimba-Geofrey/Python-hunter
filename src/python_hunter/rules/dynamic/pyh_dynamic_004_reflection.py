"""PYH-DYNAMIC-004: Reflection Control Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHDynamic004Reflection(SecurityRule):
    """Detects unsafe or dynamic reflection (getattr, setattr, globals, locals) with variable targets."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DYNAMIC-004",
            name="Unsafe Reflection Control",
            description="Use of getattr() or setattr() with dynamically computed attribute names can expose private methods or sensitive configurations.",
            category=Category.REFLECTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            cwe="CWE-470",
            owasp="A03:2021-Injection",
            remediation="Use explicit dictionary lookup or explicit attribute whitelisting instead of dynamic getattr/setattr.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for document in ast_summary.documents:
            for call in document.calls:
                if call.name in ("getattr", "setattr"):
                    line = call.location.line_start if call.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=call.location.column_start if call.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=Confidence.MEDIUM,
                            category=self.category,
                            title=self.name,
                            description=f"Dynamic reflection call detected: {call.name}()",
                            file_path=document.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=50.0,
                        )
                    )
        return findings
