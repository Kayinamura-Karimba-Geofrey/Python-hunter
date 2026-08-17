"""PYH-SECRET-002: Generic Access Token Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret002GenericAccessToken(SecretDetector):
    """Detector for access tokens and bearer tokens."""

    PATTERN = re.compile(
        r"(?i)(access[_-]?token|auth[_-]?token|bearer[_-]?token|oauth[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,128})['\"]"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-002",
            name="Generic Access Token Detector",
            secret_type=SecretType.ACCESS_TOKEN,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies access tokens and OAuth bearer tokens assigned in source code.",
            remediation="Move access tokens to external configuration or vault secret stores.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.PATTERN.finditer(line):
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
