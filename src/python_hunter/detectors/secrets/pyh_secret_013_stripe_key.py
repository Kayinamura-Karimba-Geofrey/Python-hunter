"""PYH-SECRET-013: Stripe Secret Key Detector."""

import re
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector, SecretType


class PYHSecret013StripeKey(SecretDetector):
    """Detector for Stripe API Live Secret Keys (sk_live_...)."""

    PATTERN = re.compile(r"sk_(?:live|test)_[a-zA-Z0-9]{24,34}")

    def __init__(self) -> None:
        super().__init__(
            id="PYH-SECRET-013",
            name="Stripe Live Key Detector",
            secret_type=SecretType.STRIPE_KEY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Identifies exposed Stripe live secret key credentials permitting billing operations.",
            remediation="Roll the compromised Stripe secret key in the Stripe Dashboard immediately.",
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
                        context_key="STRIPE_LIVE_KEY",
                        evidence_snippet=line.strip(),
                    )
                )
        return candidates
