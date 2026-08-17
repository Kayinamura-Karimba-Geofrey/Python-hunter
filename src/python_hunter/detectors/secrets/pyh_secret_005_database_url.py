"""PYH-SECRET-005: Database Credential URL Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret005DatabaseURL(SecretDetector):
    """Detector for embedded database credentials in connection string URIs."""

    DB_URI_PATTERN = re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:]+:([^@\s'\"]{3,})@"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-005",
            name="Database Connection Credential Detector",
            secret_type=SecretType.DATABASE_URL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies connection strings containing embedded database passwords.",
            remediation="Extract database credentials to environment variables or secret store solutions.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.DB_URI_PATTERN.finditer(line):
                full_match = match.group(0)
                password = match.group(2)
                col = match.start(2)
                candidates.append(
                    SecretCandidate(
                        value=password,
                        file_path=file_path,
                        line=line_num,
                        column=col,
                        detector_id=self.id,
                        secret_type=self.secret_type,
                        context_key="DATABASE_URL",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
