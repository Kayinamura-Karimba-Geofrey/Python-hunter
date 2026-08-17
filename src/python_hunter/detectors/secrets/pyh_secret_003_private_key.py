"""PYH-SECRET-003: Private Key Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret003PrivateKey(SecretDetector):
    """Detector for RSA, EC, DSA, OPENSSH, and PGP private key headers."""

    HEADER_PATTERN = re.compile(
        r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-003",
            name="Private Key Block Detector",
            secret_type=SecretType.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Identifies PEM, RSA, EC, or OpenSSH private key blocks embedded in files.",
            remediation="Remove private key blocks from version control immediately and revoke/rotate associated public keys.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            match = self.HEADER_PATTERN.search(line)
            if match:
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
                        context_key="PRIVATE_KEY",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
