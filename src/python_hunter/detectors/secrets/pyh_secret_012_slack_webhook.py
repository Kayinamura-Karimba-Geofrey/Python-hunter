"""PYH-SECRET-012: Slack Webhook and Token Secret Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret012SlackWebhook(SecretDetector):
    """Detector for Slack Incoming Webhook URLs and tokens."""

    PATTERN = re.compile(
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-012",
            name="Slack Webhook Detector",
            secret_type=SecretType.SLACK_WEBHOOK,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies exposed Slack Webhook URLs which permit message injection.",
            remediation="Revoke the exposed webhook URL in Slack API settings and inject via environment variables.",
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
                        context_key="SLACK_WEBHOOK_URL",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
