"""PYH-DYNAMIC-003: Unsafe YAML Loading Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHDynamic003UnsafeYAML(SecurityRule):
    """Detects unsafe yaml.load calls without SafeLoader."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-DYNAMIC-003",
            name="Unsafe YAML Loading",
            description="yaml.load() without Loader=yaml.SafeLoader can instantiate arbitrary Python objects and execute arbitrary code.",
            category=Category.UNSAFE_DESERIALIZATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            remediation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader to yaml.load().",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for document in ast_summary.documents:
            for call in document.calls:
                if call.name in ("yaml.load", "yaml.unsafe_load"):
                    line = call.location.line_start if call.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=call.location.column_start if call.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            category=self.category,
                            title=self.name,
                            description=f"Potentially unsafe YAML load call detected: {call.name}()",
                            file_path=document.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=80.0,
                        )
                    )
        return findings
