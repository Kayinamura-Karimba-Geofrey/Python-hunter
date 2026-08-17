"""PYH-SECRET-010: High-Entropy Credential Candidate Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.entropy import EntropyCalculator
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret010HighEntropy(SecretDetector):
    """Detector for high-entropy string literals assigned to secret-like variables."""

    ASSIGNMENT_PATTERN = re.compile(
        r"(?i)(secret|key|token|auth|credential|sign|encrypt|private)\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{16,})['\"]"
    )

    MIN_ENTROPY = 3.5

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-010",
            name="High-Entropy Credential Candidate Detector",
            secret_type=SecretType.GENERIC_SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Identifies high Shannon entropy string literals assigned to security-sensitive variable names.",
            remediation="Review high entropy strings to ensure raw credentials or signing keys are not hardcoded.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.ASSIGNMENT_PATTERN.finditer(line):
                var_name = match.group(1)
                secret_val = match.group(2)
                col = match.start(2)

                entropy = EntropyCalculator.calculate(secret_val)
                if entropy >= self.MIN_ENTROPY:
                    candidates.append(
                        SecretCandidate(
                            value=secret_val,
                            file_path=file_path,
                            line=line_num,
                            column=col,
                            detector_id=self.id,
                            secret_type=self.secret_type,
                            context_key=var_name,
                            entropy=entropy,
                            evidence_snippet=line.strip(),
                        )
                    )
        return candidates
