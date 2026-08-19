"""PYH-DYNAMIC-005: Unrestricted Dynamic Import Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHDynamic005DynamicImport(SecurityRule):
    """Detects unrestricted dynamic imports (__import__, importlib.import_module)."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DYNAMIC-005",
            name="Unrestricted Dynamic Import",
            description="Dynamic module importing via __import__() or importlib.import_module() using variable module names can lead to arbitrary code execution if module names are controlled by untrusted inputs.",
            category=Category.DYNAMIC_IMPORT,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe="CWE-706",
            owasp="A08:2021-Software and Data Integrity Failures",
            remediation="Use explicit module mappings or validate requested module names against a strict allowlist.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for document in ast_summary.documents:
            for call in document.calls:
                if call.name in ("__import__", "importlib.import_module", "import_module"):
                    line = call.location.line_start if call.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=call.location.column_start if call.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            category=self.category,
                            title=self.name,
                            description=f"Dynamic module import call detected: {call.name}()",
                            file_path=document.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=75.0,
                        )
                    )
        return findings
