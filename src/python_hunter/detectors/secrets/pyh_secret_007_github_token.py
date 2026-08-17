"""PYH-SECRET-007: GitHub Token Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret007GitHubToken(SecretDetector):
    """Detector for GitHub Personal Access Tokens and OAuth tokens."""

    GITHUB_TOKEN_PATTERN = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b")

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-007",
            name="GitHub Token Detector",
            secret_type=SecretType.AUTH_TOKEN,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_, ghr_) exposed in code.",
            remediation="Revoke the exposed GitHub token immediately in GitHub settings and regenerate a fine-grained token.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.GITHUB_TOKEN_PATTERN.finditer(line):
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
                        context_key="GITHUB_TOKEN",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
