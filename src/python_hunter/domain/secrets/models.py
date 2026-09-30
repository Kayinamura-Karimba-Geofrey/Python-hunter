"""Secret Detection Domain Models, Taxonomy, Value Objects, and Non-Reversible Fingerprinting."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional

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
    GCP_KEY = "GCP_KEY"
    STRIPE_KEY = "STRIPE_KEY"
    SLACK_WEBHOOK = "SLACK_WEBHOOK"
    GENERIC_SECRET = "GENERIC_SECRET"


class ExposureType(str, Enum):
    """Taxonomy of secret exposure locations and accessibility levels."""

    PUBLIC_REPOSITORY = "PUBLIC_REPOSITORY"
    PRIVATE_REPOSITORY = "PRIVATE_REPOSITORY"
    LOCAL_PROJECT = "LOCAL_PROJECT"
    GIT_HISTORY = "GIT_HISTORY"
    DOCUMENTATION = "DOCUMENTATION"
    CI_CD = "CI_CD"


class SecretEnvironment(str, Enum):
    """Execution environment context of the exposed credential."""

    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    UNKNOWN = "UNKNOWN"


class SecretPrivilege(str, Enum):
    """Potential privilege scope of the exposed credential."""

    READ = "READ"
    WRITE = "WRITE"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    DATABASE = "DATABASE"
    CLOUD = "CLOUD"
    SIGNING = "SIGNING"
    UNKNOWN = "UNKNOWN"


def _fingerprint_salt() -> str:
    """V-11: per-installation random salt for secret fingerprints.

    A static salt embedded in the source lets an attacker who obtains a database of
    fingerprints brute-force candidate secrets offline. A random per-install salt
    (generated once, stored next to other local state with user-only permissions)
    keeps fingerprints stable within one machine while making cross-target
    dictionary attacks infeasible.
    """
    import os

    salt_file = os.path.join(
        os.getenv("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"),
        "python_hunter",
        "fp_salt",
    )
    try:
        os.makedirs(os.path.dirname(salt_file), mode=0o700, exist_ok=True)
        if os.path.exists(salt_file) and not os.path.islink(salt_file):
            with open(salt_file, "r", encoding="utf-8") as f:
                stored = f.read().strip()
                if stored:
                    return stored
        salt = os.urandom(32).hex()
        fd = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(salt)
        return salt
    except Exception:
        # Last resort: ephemeral random salt. Fingerprints remain valid for this
        # process run only, which still prevents offline cross-target correlation.
        return os.urandom(32).hex()


def compute_secret_fingerprint(secret_val: str) -> str:
    """Computes a non-reversible keyed SHA-256 fingerprint for secret identification without storing raw credentials."""
    if not secret_val:
        return ""
    salt = _fingerprint_salt()
    hasher = hashlib.sha256()
    hasher.update(f"{salt}:{secret_val.strip()}".encode("utf-8"))
    return f"sec_fp_{hasher.hexdigest()[:32]}"


@dataclass
class SecretExposure:
    """Detailed exposure metadata of a detected secret."""

    exposure_type: ExposureType = ExposureType.LOCAL_PROJECT
    environment: SecretEnvironment = SecretEnvironment.UNKNOWN
    privilege: SecretPrivilege = SecretPrivilege.UNKNOWN
    repository_visibility: str = "PRIVATE"
    is_historical: bool = False
    is_deleted: bool = False
    commit_sha: str = ""
    commit_author: str = ""
    commit_date: str = ""


@dataclass
class SecretCandidate:
    """In-memory raw secret candidate extracted prior to validation, fingerprinting, and redaction."""

    value: str  # Transient, never persisted to disk or serialized to findings
    file_path: str
    line: int
    column: int
    detector_id: str
    secret_type: SecretType
    secret_id: str = ""
    fingerprint: str = ""
    context_key: str = ""
    entropy: float = 0.0
    confidence: Confidence = Confidence.HIGH
    exposure: SecretExposure = field(default_factory=SecretExposure)
    evidence_snippet: str = ""
    is_test_file: bool = False
    is_placeholder: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint and self.value:
            self.fingerprint = compute_secret_fingerprint(self.value)


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
