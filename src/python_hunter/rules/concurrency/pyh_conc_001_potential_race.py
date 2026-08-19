"""PYH-CONC-001: Potential Race Condition Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHConc001PotentialRace(SecurityRule):
    """Detects potential race conditions on shared mutable state across threads/tasks."""

    def __init__(self) -> None:
        super().__init__(
            id="PYH-CONC-001",
            name="Potential Race Condition",
            description="Unsynchronized concurrent reads or writes to shared state can cause data corruption or unexpected behavior.",
            category=Category.CONCURRENCY_RISK,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            cwe="CWE-362",
            owasp="A04:2021-Insecure Design",
            remediation="Use locks (threading.Lock, asyncio.Lock) or thread-safe atomic primitives to protect shared state.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings = []
        for doc in ast_summary.documents:
            for stmt in doc.statements:
                if "global " in stmt.code_snippet or "nonlocal " in stmt.code_snippet:
                    line = stmt.location.line_start if stmt.location else 1
                    loc = Location(line_start=line, line_end=line, column_start=stmt.location.column_start if stmt.location else 0)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=self.name,
                            description="Global variable access in concurrent scope without explicit synchronization.",
                            file_path=doc.file_path,
                            location=loc,
                            remediation=self.remediation,
                            risk_score=50.0,
                        )
                    )
        return findings
