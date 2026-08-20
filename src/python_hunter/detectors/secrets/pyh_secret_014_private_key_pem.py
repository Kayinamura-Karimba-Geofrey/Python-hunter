"""PYH-SECRET-014: RSA/EC/PGP Private Key PEM Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret014PrivateKeyPEM(SecretDetector):
    """Detector for RSA, EC, DSA, and PGP Private Key blocks."""

    PATTERN = re.compile(
        r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----[\s\S]+?-----END\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-014",
            name="Private Key PEM Detector",
            secret_type=SecretType.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Identifies exposed unencrypted RSA, EC, OPENSSH, or PGP private key blocks.",
            remediation="Revoke the exposed keypair immediately and remove private key content from source files.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for match in self.PATTERN.finditer(content):
            secret_val = match.group(0)
            # Find line number of start
            line_num = content[:match.start()].count("\n") + 1
            candidates.append(
                SecretCandidate(
                    value=secret_val,
                    file_path=file_path,
                    line=line_num,
                    column=1,
                    detector_id=self.id,
                    secret_type=self.secret_type,
                    context_key="PEM_PRIVATE_KEY",
                    evidence_snippet="-----BEGIN PRIVATE KEY----- [REDACTED BLOCK]",
                )
            )
        return candidates
