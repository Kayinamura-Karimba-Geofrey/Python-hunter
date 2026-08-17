"""PYH-AST-003: Dangerous compile() Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHAST003Compile(SecurityRule):
    """Rule detecting calls to compile() for dynamic code generation."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-AST-003",
            name="Dangerous compile() usage",
            description="Compiling dynamically constructed string source into AST/code objects can lead to arbitrary code execution.",
            category=Category.CODE_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            remediation="Ensure source strings passed to compile() are statically verified or strictly vetted.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for doc in ast_summary.documents:
            for call in doc.calls:
                if call.qualified_name == "compile":
                    l_start = call.location.line_start if call.location else 1
                    l_end = call.location.line_end if call.location and call.location.line_end else l_start
                    c_start = call.location.column_start if call.location else 0
                    c_end = call.location.column_end if call.location else 0
                    loc = Location(line_start=l_start, line_end=l_end, column_start=c_start, column_end=c_end)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=self.name,
                            description=self.description,
                            file_path=doc.file_path,
                            location=loc,
                            evidence=f"Call to code compiler '{call.name}()'",
                            remediation=self.remediation,
                        )
                    )
        return findings
