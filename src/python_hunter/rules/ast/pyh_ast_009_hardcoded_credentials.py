"""PYH-AST-009: Hardcoded Credential Assignment Security Rule."""

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import SecurityRule


class PYHAST009HardcodedCredentials(SecurityRule):
    """Rule detecting obvious assignments of sensitive variable names to non-empty string literals."""

    SECRET_KEYWORDS = {
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "SECRET_KEY",
        "SECRET",
        "AUTH_TOKEN",
        "PRIVATE_KEY",
    }

    def __init__(self) -> None:
        super().__init__(
            id="PYH-AST-009",
            name="Obvious hardcoded credential assignment",
            description="Hardcoding API keys, passwords, or secrets directly in source code risks exposing credentials in repositories.",
            category=Category.SECRET_LEAK,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            remediation="Extract sensitive credentials to environment variables or dedicated secret management services.",
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for doc in ast_summary.documents:
            for assign in doc.assignments:
                tgt_upper = assign.target.upper()
                if assign.value_type in ("Constant", "str") and any(kw == tgt_upper or kw in tgt_upper for kw in self.SECRET_KEYWORDS):
                    l_start = assign.location.line_start if assign.location else 1
                    l_end = assign.location.line_end if assign.location and assign.location.line_end else l_start
                    c_start = assign.location.column_start if assign.location else 0
                    c_end = assign.location.column_end if assign.location else 0
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
                            evidence=f"Assignment to credential variable '{assign.target}'",
                            remediation=self.remediation,
                        )
                    )
        return findings
