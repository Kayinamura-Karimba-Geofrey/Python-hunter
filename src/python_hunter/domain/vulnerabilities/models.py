"""Vulnerability Intelligence Domain Models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.dependencies.models import Dependency
from python_hunter.domain.dependencies.normalization import normalize_package_name


class IdentifierType(str, Enum):
    """Normalized vulnerability identifier types."""

    CVE = "CVE"
    GHSA = "GHSA"
    PYSEC = "PYSEC"
    OSV = "OSV"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, raw_id: str) -> "IdentifierType":
        """Determine identifier type from raw ID prefix."""
        raw_upper = raw_id.strip().upper()
        if raw_upper.startswith("CVE-"):
            return cls.CVE
        if raw_upper.startswith("GHSA-"):
            return cls.GHSA
        if raw_upper.startswith("PYSEC-"):
            return cls.PYSEC
        if raw_upper.startswith("OSV-"):
            return cls.OSV
        return cls.UNKNOWN


@dataclass(frozen=True)
class VulnerabilityIdentifier:
    """Normalized vulnerability identifier value object."""

    id_type: IdentifierType
    raw_id: str

    def __post_init__(self) -> None:
        if not self.raw_id:
            raise ValueError("raw_id cannot be empty")


@dataclass(frozen=True)
class PackageIdentity:
    """Package ecosystem identity value object."""

    ecosystem: str  # e.g. "PyPI"
    name: str  # Raw package name
    normalized_name: str = field(init=False)
    namespace: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Package name cannot be empty")
        object.__setattr__(self, "normalized_name", normalize_package_name(self.name))


@dataclass
class CVSS:
    """Normalized CVSS metric score and vector."""

    version: str  # e.g., "3.1"
    base_score: float
    vector_string: str = ""
    severity: Severity = Severity.MEDIUM


@dataclass
class AffectedRange:
    """Affected version range representation."""

    range_type: str  # e.g., "ECOSYSTEM", "SEMVER", "GIT"
    events: list[dict[str, str]] = field(default_factory=list)  # e.g., [{"introduced": "0"}, {"fixed": "1.2.3"}]
    database_specific: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Normalized vulnerability record entity."""

    id: str  # Primary ID, e.g. GHSA-xxxx-xxxx-xxxx or CVE-2023-xxxx
    summary: str
    description: str = ""
    aliases: list[str] = field(default_factory=list)
    affected_ecosystem: str = "PyPI"
    affected_package: str = ""  # Normalized name
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss: CVSS | None = None
    references: list[str] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    source: str = "OSV"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_withdrawn(self) -> bool:
        """Check if vulnerability record has been withdrawn."""
        return self.withdrawn_at is not None

    @property
    def normalized_identifiers(self) -> list[VulnerabilityIdentifier]:
        """Extract all normalized identifiers (primary + aliases)."""
        ids = [self.id] + [a for a in self.aliases if a != self.id]
        return [VulnerabilityIdentifier(IdentifierType.from_string(i), i) for i in ids]


class VulnerabilityStatus(str, Enum):
    """Status of vulnerability evaluation against a dependency."""

    NOT_AFFECTED = "NOT_AFFECTED"
    AFFECTED = "AFFECTED"
    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    UNKNOWN = "UNKNOWN"
    WITHDRAWN = "WITHDRAWN"
    FIXED = "FIXED"


@dataclass
class VulnerabilityMatch:
    """Match result associating a vulnerability record with a dependency."""

    vulnerability: Vulnerability
    dependency: Dependency
    status: VulnerabilityStatus
    dependency_paths: list[list[str]] = field(default_factory=list)
    recommended_fix: str | None = None
    constraint_compatible: bool = True
    explanation: str = ""
