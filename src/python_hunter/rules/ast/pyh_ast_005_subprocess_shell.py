"""PYH-AST-005: Dangerous subprocess shell=True Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHAST005SubprocessShell(SecurityRule):
    """Rule detecting subprocess calls invoked with shell=True."""

    SUBPROCESS_FUNCS = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
    }

    def __init__(self) -> None:
        super().__init__(
            id="PYH-AST-005",
            name="Dangerous subprocess shell=True execution",
            description="Invoking subprocess commands with shell=True enables shell interpolation and risks command injection vulnerabilities.",
            category=Category.CODE_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            remediation="Set shell=False (default) and pass command and arguments as a sequence list.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for doc in ast_summary.documents:
            for call in doc.calls:
                if call.qualified_name in self.SUBPROCESS_FUNCS:
                    shell_val = call.keyword_arguments.get("shell")
                    if shell_val and shell_val not in ("False", "0", "None"):
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
                                evidence=f"Subprocess call '{call.qualified_name}' executed with shell=True keyword argument",
                                remediation=self.remediation,
                            )
                        )
        return findings
