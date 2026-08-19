"""PYH-CONC-003: TOCTOU Vulnerability Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHConc003TOCTOU(SecurityRule):
    """Detects Time-of-Check to Time-of-Use (TOCTOU) file, permission, or state race conditions."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-CONC-003",
            name="Time-of-Check to Time-of-Use (TOCTOU)",
            description="A resource state check (e.g. os.path.exists) followed by operation (e.g. open) without atomicity allows attackers to modify the target in between.",
            category=Category.CONCURRENCY_RISK,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-367",
            owasp="A01:2021-Broken Access Control",
            remediation="Perform atomic operations or handle exceptions directly (e.g. try/except FileNotFoundError, O_CREAT | O_EXCL flags).",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for doc in ast_summary.documents:
            code_text = "\n".join(doc.source_lines)
            if ("os.path.exists" in code_text or "os.access" in code_text) and ("open(" in code_text or "os.remove" in code_text):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=self.name,
                        description="Potential TOCTOU race condition detected between check (exists/access) and file operation.",
                        file_path=doc.file_path,
                        location=Location(line_start=1, line_end=1),
                        remediation=self.remediation,
                        risk_score=75.0,
                    )
                )
        return findings
