"""PYH-SECRET-011: Google Cloud Platform (GCP) API Key Secret Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret011GCPAPIKey(SecretDetector):
    """Detector for GCP API Keys (AIzaSy...)."""

    PATTERN = re.compile(r"AIzaSy[a-zA-Z0-9_\-]{30,35}")

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-011",
            name="GCP API Key Detector",
            secret_type=SecretType.GCP_KEY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies exposed Google Cloud Platform API key strings.",
            remediation="Revoke the exposed GCP API key in Google Cloud Console and use IAM service accounts.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.PATTERN.finditer(line):
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
                        context_key="GCP_API_KEY",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
