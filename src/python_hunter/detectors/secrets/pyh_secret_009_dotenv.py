"""PYH-SECRET-009: Environment File Secret Detector."""

import os
import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret009Dotenv(SecretDetector):
    """Detector for secret key-value assignments inside .env and environment files."""

    DOTENV_PATTERN = re.compile(
        r"^(?:export\s+)?([A-Z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|CREDENTIAL|PRIVATE)[A-Z0-9_]*)\s*=\s*['\"]?([^'\"\s\n]{8,})['\"]?$"
    )

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-009",
            name="Environment File Secret Detector",
            secret_type=SecretType.GENERIC_SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Identifies secrets committed inside environment configuration files (.env, .env.local).",
            remediation="Ensure .env files containing real production secrets are excluded from Git repository history via .gitignore.",
        )

    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        basename = os.path.basename(file_path).lower()
        if not (basename.startswith(".env") or basename.endswith((".env", ".cfg", ".ini"))):
            return candidates
        for line_num, line in enumerate(content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            match = self.DOTENV_PATTERN.match(line_str)
            if match:
                key_name = match.group(1)
                secret_val = match.group(2)
                col = line.find(secret_val)
                candidates.append(
                    SecretCandidate(
                        value=secret_val,
                        file_path=file_path,
                        line=line_num,
                        column=max(0, col),
                        detector_id=self.id,
                        secret_type=self.secret_type,
                        context_key=key_name,
                        evidence_snippet=line_str,
                    )
                )
        return candidates
