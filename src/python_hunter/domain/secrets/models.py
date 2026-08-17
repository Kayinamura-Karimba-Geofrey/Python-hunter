"""Secret Detection Domain Models and Contracts."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Confidence, Severity


class SecretType(str, Enum):
    """Taxonomy of detectable credential and secret types."""

    API_KEY = "API_KEY"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    AUTH_TOKEN = "AUTH_TOKEN"
    BEARER_TOKEN = "BEARER_TOKEN"
    PASSWORD = "PASSWORD"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    DATABASE_URL = "DATABASE_URL"
    PRIVATE_KEY = "PRIVATE_KEY"
    SSH_KEY = "SSH_KEY"
    JWT = "JWT"
    WEBHOOK_SECRET = "WEBHOOK_SECRET"
    ENCRYPTION_KEY = "ENCRYPTION_KEY"
    SIGNING_KEY = "SIGNING_KEY"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    SERVICE_CREDENTIAL = "SERVICE_CREDENTIAL"
    GENERIC_SECRET = "GENERIC_SECRET"


@dataclass
class SecretCandidate:
    """In-memory raw secret candidate extracted prior to validation and redaction."""

    value: str
    file_path: str
    line: int
    column: int
    detector_id: str
    secret_type: SecretType
    context_key: str = ""
    entropy: float = 0.0
    evidence_snippet: str = ""


@dataclass
class SecretDetector(ABC):
    """Abstract base class for all secret detectors."""

    id: str
    name: str
    secret_type: SecretType
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    @abstractmethod
    def detect(self, content: str, file_path: str, context: AnalysisContext) -> list[SecretCandidate]:
        """Scan file content text for secret candidates."""
