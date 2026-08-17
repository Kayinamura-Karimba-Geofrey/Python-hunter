"""PYH-SECRET-008: Generic Password Assignment Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret008GenericPassword(SecretDetector):
    """Detector for hardcoded password assignments."""

    PASSWORD_PATTERN = re.compile(
        r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{6,64})['\"]"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-008",
            name="Generic Password Assignment Detector",
            secret_type=SecretType.PASSWORD,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Identifies hardcoded plaintext password assignments in code.",
            remediation="Extract passwords to environment variables or dynamic secret managers.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.PASSWORD_PATTERN.finditer(line):
                var_name = match.group(1)
                secret_val = match.group(2)
                col = match.start(2)
                candidates.append(
                    SecretCandidate(
                        value=secret_val,
                        file_path=file_path,
                        line=line_num,
                        column=col,
                        detector_id=self.id,
                        secret_type=self.secret_type,
                        context_key=var_name,
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
