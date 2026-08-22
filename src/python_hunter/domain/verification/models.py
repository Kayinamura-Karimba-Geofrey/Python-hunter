"""Verification Domain Models and Authorization Objects."""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import hashlib

from python_hunter.domain.common.enums import (
    VerificationStatus,
    VerificationConfidence,
    VerificationMode,
    TestSafetyLevel,
)


@dataclass
class VerificationResult:
    """Represents the evidence and status of a security verification attempt."""

    finding_id: str
    verification_status: VerificationStatus
    confidence: VerificationConfidence
    evidence: str
    test_method: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    environment: str = "local_sandbox"
    safety_level: TestSafetyLevel = TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE
    test_version: str = "1.0.0"
    scanner_version: str = "1.0.0"
    execution_time_ms: float = 0.0
    test_hash: str = ""
    tamper_proof_signature: str = ""

    def __post_init__(self) -> None:
        if not self.test_hash:
            raw = f"{self.finding_id}:{self.verification_status}:{self.timestamp}:{self.evidence}"
            self.test_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if not self.tamper_proof_signature:
            self.tamper_proof_signature = f"sig-sha256-{self.test_hash[:16]}"


@dataclass
class SecurityTest:
    """Represents a controlled, non-destructive test case."""

    test_id: str
    vulnerability_type: str
    preconditions: List[str]
    input_payload: str
    expected_behavior: str
    safety_level: TestSafetyLevel = TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE
    description: str = ""


@dataclass
class VerificationAuthorization:
    """Explicit, non-permanent authorization record required for active verification."""

    target: str
    scope: str
    authorized_by: str
    expiration: datetime
    allowed_networks: List[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allowed_environment: str = "local_test_environment"

    @property
    def is_valid(self) -> bool:
        """Check if authorization has not expired."""
        return datetime.now(timezone.utc) <= self.expiration

    @staticmethod
    def create_temporary_authorization(
        target: str, authorized_by: str = "security_operator", valid_minutes: int = 60
    ) -> "VerificationAuthorization":
        """Factory for short-lived authorizations."""
        exp = datetime.now(timezone.utc) + timedelta(minutes=valid_minutes)
        return VerificationAuthorization(
            target=target,
            scope="non_destructive_verification",
            authorized_by=authorized_by,
            expiration=exp,
        )
