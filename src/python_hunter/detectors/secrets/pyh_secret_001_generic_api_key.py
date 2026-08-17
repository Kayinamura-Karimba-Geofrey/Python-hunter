"""PYH-SECRET-001: Generic API Key Secret Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret001GenericAPIKey(SecretDetector):
    """Detector for generic API key assignments and patterns."""

    PATTERN = re.compile(
        r"(?i)(api[_-]?key|apikey|x[_-]api[_-]key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-001",
            name="Generic API Key Detector",
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies generic API key credential strings assigned in code or configurations.",
            remediation="Extract API keys to environment variables or secret managers.",
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
