"""PYH-AST-006: Unsafe Pickle Deserialization Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHAST006Pickle(SecurityRule):
    """Rule detecting calls to pickle.loads() and pickle.load()."""

    PICKLE_FUNCS = {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"}

    def __init__(self) -> None:
        super().__init__(
            id="PYH-AST-006",
            name="Unsafe pickle deserialization",
            description="Deserializing untrusted pickle streams can result in arbitrary remote code execution via __reduce__ payloads.",
            category=Category.UNSAFE_DESERIALIZATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            remediation="Use safe serialization formats like JSON, Protocol Buffers, or msgpack for untrusted data.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for doc in ast_summary.documents:
            for call in doc.calls:
                if call.qualified_name in self.PICKLE_FUNCS:
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
                            evidence=f"Call to deserializer '{call.name}()' (resolved: '{call.qualified_name}')",
                            remediation=self.remediation,
                        )
                    )
        return findings
