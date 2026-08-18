"""PYH-DYNAMIC-001: Dynamic Code Execution Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHDynamic001EvalExec(SecurityRule):
    """Detects dangerous dynamic execution functions (eval, exec, compile)."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DYNAMIC-001",
            name="Dynamic Code Execution",
            description="Use of eval(), exec(), or compile() permits dynamic code execution, which can lead to arbitrary code execution if inputs are controlled by attackers.",
            category=Category.DYNAMIC_EXECUTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            remediation="Avoid eval() or exec(). Use static function dispatch, ast.literal_eval() for data parsing, or safe expression evaluation libraries.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for document in ast_summary.documents:
            for call in document.calls:
                if call.name in ("eval", "exec", "compile"):
                    line = call.location.line_start if call.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=call.location.column_start if call.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            category=self.category,
                            title=self.name,
                            description=f"Dynamic code execution call detected: {call.name}()",
                            file_path=document.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=85.0 if call.name in ("eval", "exec") else 60.0,
                        )
                    )
        return findings
