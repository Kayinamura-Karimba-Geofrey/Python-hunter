"""PYH-SECRET-006: AWS Credentials Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret006AWSCredentials(SecretDetector):
    """Detector for AWS Access Key ID and AWS Secret Access Key patterns."""

    AWS_KEY_PATTERN = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-006",
            name="AWS Access Key Detector",
            secret_type=SecretType.CLOUD_CREDENTIAL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies AWS Access Key IDs (AKIA/ASIA) hardcoded in repository files.",
            remediation="Deactivate exposed AWS access keys via AWS IAM management console and transition to IAM roles.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.AWS_KEY_PATTERN.finditer(line):
                secret_val = match.group(1)
                col = match.start(1)
                candidates.append(
                    SecretCandidate(
                        value=secret_val,
                        file_path=file_path,
                        line=line_num,
                        column=col,
                        detector_id=self.id,
                        secret_type=self.secret_type,
                        context_key="AWS_ACCESS_KEY_ID",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
