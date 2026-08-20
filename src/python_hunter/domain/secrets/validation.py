"""Offline-First Secret Validation Engine and External Validation Interfaces."""

from abc import ABC, abstractmethod
import re
from typing import Any, Dict, Optional
from python_hunter.domain.secrets.models import SecretCandidate, SecretType


class SecretValidator:
    """Offline-first structural and format validator for secret candidates."""

    STRUCTURAL_PATTERNS = {
        SecretType.CLOUD_CREDENTIAL: re.compile(r"^AKIA[0-9A-Z]{16}$"),
        SecretType.GCP_KEY: re.compile(r"^AIzaSy[a-zA-Z0-9_\-]{30,35}$"),
        SecretType.ACCESS_TOKEN: re.compile(r"^(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}$"),
        SecretType.STRIPE_KEY: re.compile(r"^(sk|pk)_(live|test)_[a-zA-Z0-9]{24,34}$"),
        SecretType.JWT: re.compile(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"),
        SecretType.SLACK_WEBHOOK: re.compile(r"^https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+$"),
    }

    @classmethod
    def validate_structurally(cls, candidate: SecretCandidate) -> bool:
        """Performs offline structural validation based on format, checksums, and regex specifications."""
        val = candidate.value.strip().strip("'\"")
        if not val:
            return False

        # Private Key Check
        if candidate.secret_type == SecretType.PRIVATE_KEY:
            return "-----BEGIN" in val and "PRIVATE KEY-----" in val

        # Provider-specific regex match
        pattern = cls.STRUCTURAL_PATTERNS.get(candidate.secret_type)
        if pattern:
            return bool(pattern.match(val))

        # Generic validation: minimum length and printable ASCII
        return len(val) >= 12 and all(32 <= ord(c) <= 126 for c in val)


class ExternalValidationProvider(ABC):
    """Opt-in external validation provider interface (Disabled by default; zero network calls allowed unless explicitly configured)."""

    @abstractmethod
    def validate_externally(self, candidate: SecretCandidate) -> Dict[str, Any]:
        """Validate credential state against external API endpoint with strict privacy controls."""
        pass


class DummyExternalValidationProvider(ExternalValidationProvider):
    """Safe fallback external validation provider ensuring zero network traffic."""

    def validate_externally(self, candidate: SecretCandidate) -> Dict[str, Any]:
        return {
            "validated": False,
            "status": "EXTERNAL_VALIDATION_DISABLED",
            "message": "External secret validation is disabled by default to prevent secret exposure.",
        }
