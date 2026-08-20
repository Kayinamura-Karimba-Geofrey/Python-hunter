"""PYH-SECRET-015: Database Connection URL Secret Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret015DatabaseConnectionURL(SecretDetector):
    """Detector for PostgreSQL, MySQL, MongoDB, Redis connection URLs with embedded passwords."""

    PATTERN = re.compile(
        r"(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss)://([a-zA-Z0-9_\-]+):([^@\s'\"]+)@([a-zA-Z0-9_\-\.]+)"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-015",
            name="Database Connection URL Detector",
            secret_type=SecretType.DATABASE_URL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies database connection strings containing hard-coded username and password credentials.",
            remediation="Extract database credentials into environment variables or secrets manager.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.PATTERN.finditer(line):
                full_url = match.group(0)
                password = match.group(3)
                col = match.start(0)
                candidates.append(
                    SecretCandidate(
                        value=full_url,
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
