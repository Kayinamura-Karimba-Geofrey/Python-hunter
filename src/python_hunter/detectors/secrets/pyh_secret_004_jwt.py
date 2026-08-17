"""PYH-SECRET-004: JWT Token Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret004JWT(SecretDetector):
    """Detector for JSON Web Tokens (JWT)."""

    JWT_PATTERN = re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-004",
            name="JWT Token Detector",
            secret_type=SecretType.JWT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies hardcoded JSON Web Tokens (JWT) containing encoded headers, payloads, and signatures.",
            remediation="Never commit hardcoded JWT tokens. Generate tokens dynamically using secure key management.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.JWT_PATTERN.finditer(line):
                secret_val = match.group(0)
                col = match.start(0)
                candidates.append(
                    SecretCandidate(
                        value=secret_val,
                        file_path=file_path,
                        line=line_num,
                        column=col,
                        detector_id=self.id,
                        secret_type=self.secret_type,
                        context_key="JWT",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
