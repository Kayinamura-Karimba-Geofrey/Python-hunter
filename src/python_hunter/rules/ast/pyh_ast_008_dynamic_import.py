"""PYH-AST-008: Dynamic Import Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHAST008DynamicImport(SecurityRule):
    """Rule detecting calls to __import__() or importlib.import_module()."""

    DYNAMIC_IMPORT_FUNCS = {"__import__", "importlib.import_module"}

    def __init__(self) -> None:
        super().__init__(
            id="PYH-AST-008",
            name="Dynamic module import execution",
            description="Dynamically importing modules via string names can allow unauthorized code execution if input module names are untrusted.",
            category=Category.CODE_INJECTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            cwe="CWE-706",
            owasp="A03:2021-Injection",
            remediation="Validate module names against a strict allowlist before passing them to dynamic import functions.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for doc in ast_summary.documents:
            for call in doc.calls:
                if call.qualified_name in self.DYNAMIC_IMPORT_FUNCS:
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
                            evidence=f"Call to dynamic import function '{call.name}()'",
                            remediation=self.remediation,
                        )
                    )
        return findings
