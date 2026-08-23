"""Security Intelligence Domain Models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.dependencies.normalization import normalize_package_name


class FactOrigin(str, Enum):
    """Fact classification for evidence transparency."""

    FACT = "FACT"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    STATIC_INFERENCE = "STATIC_INFERENCE"
    INTERNAL_ANALYSIS = "INTERNAL_ANALYSIS"
    USER_PROVIDED = "USER_PROVIDED"
    UNKNOWN = "UNKNOWN"


class SourceTrustLevel(int, Enum):
    """Source trust priority level for conflict resolution."""

    OFFICIAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    UNKNOWN = 1


class IntelligenceFreshnessState(str, Enum):
    """Dataset freshness state."""

    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"


class VulnerabilityLifecycleState(str, Enum):
    """Vulnerability record lifecycle states."""

    DISCOVERED = "DISCOVERED"
    PUBLISHED = "PUBLISHED"
    UPDATED = "UPDATED"
    FIXED = "FIXED"
    DEPRECATED = "DEPRECATED"
    WITHDRAWN = "WITHDRAWN"


class ExploitStatus(str, Enum):
    """Exploit availability status."""

    UNKNOWN = "UNKNOWN"
    NONE_KNOWN = "NONE_KNOWN"
    PUBLIC_REFERENCE = "PUBLIC_REFERENCE"
    VERIFIED_IN_LOCAL_TEST = "VERIFIED_IN_LOCAL_TEST"


class Ecosystem(str, Enum):
    """Supported package ecosystems."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    CARGO = "Cargo"
    COMPOSER = "Composer"
    RUBYGEMS = "RubyGems"
    NUGET = "NuGet"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def normalize(cls, val: str) -> "Ecosystem":
        v = val.strip().lower()
        mapping = {
            "pypi": cls.PYPI,
            "python": cls.PYPI,
            "npm": cls.NPM,
            "javascript": cls.NPM,
            "maven": cls.MAVEN,
            "java": cls.MAVEN,
            "go": cls.GO,
            "golang": cls.GO,
            "cargo": cls.CARGO,
            "crates": cls.CARGO,
            "rust": cls.CARGO,
            "composer": cls.COMPOSER,
            "php": cls.COMPOSER,
            "rubygems": cls.RUBYGEMS,
            "ruby": cls.RUBYGEMS,
            "nuget": cls.NUGET,
            "dotnet": cls.NUGET,
        }
        return mapping.get(v, cls.UNKNOWN)


@dataclass(frozen=True)
class PackageIdentity:
    """Package ecosystem identity value object."""

    ecosystem: str
    name: str
    normalized_name: str = field(init=False)
    namespace: str | None = None
    package_manager: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Package name cannot be empty")
        norm = normalize_package_name(self.name)
        object.__setattr__(self, "normalized_name", norm)


@dataclass
class EPSSData:
    """Exploit Prediction Scoring System (EPSS) data."""

    score: float
    percentile: float
    date: str | None = None


@dataclass
class CVSSData:
    """CVSS score vector representation."""

    version: str  # e.g. "3.1" or "4.0"
    base_score: float
    vector_string: str = ""
    temporal_score: float | None = None
    environmental_score: float | None = None
    severity: Severity = Severity.MEDIUM


@dataclass
class ExploitMetadata:
    """Exploit availability metadata."""

    exploit_available: bool = False
    exploit_maturity: str = "unproven"  # high, functional, poc, unproven
    public_exploit_reference: list[str] = field(default_factory=list)
    status: ExploitStatus = ExploitStatus.NONE_KNOWN


@dataclass
class VulnerabilityHistoryEntry:
    """Historical audit entry for vulnerability changes."""

    timestamp: datetime
    field_changed: str
    old_value: Any
    new_value: Any
    source: str


@dataclass
class IntelligenceFreshness:
    """Metadata tracking dataset freshness."""

    source: str
    version: str
    fetched_at: datetime
    published_at: datetime | None = None
    updated_at: datetime | None = None
    freshness: IntelligenceFreshnessState = IntelligenceFreshnessState.FRESH


@dataclass
class ConflictRecord:
    """Record of conflicting intelligence between sources."""

    property_name: str
    sources: dict[str, Any]
    canonical_value: Any
    resolution_explanation: str


@dataclass
class VulnerabilityRecord:
    """Comprehensive canonical Vulnerability Record in Security Intelligence Engine."""

    vulnerability_id: str  # Primary ID, e.g. CVE-2023-1234 or GHSA-xxxx-xxxx
    aliases: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cvss: CVSSData | None = None
    epss: EPSSData | None = None
    cwe: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    affected_packages: list[dict[str, Any]] = field(default_factory=list)  # ecosystem, package, range
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    lifecycle_state: VulnerabilityLifecycleState = VulnerabilityLifecycleState.PUBLISHED
    exploit_metadata: ExploitMetadata = field(default_factory=ExploitMetadata)
    source: str = "UNKNOWN"
    source_trust: SourceTrustLevel = SourceTrustLevel.UNKNOWN
    fact_origin: FactOrigin = FactOrigin.EXTERNAL_INTELLIGENCE
    conflicts: list[ConflictRecord] = field(default_factory=list)
    history: list[VulnerabilityHistoryEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_at is not None or self.lifecycle_state == VulnerabilityLifecycleState.WITHDRAWN

    def all_identifiers(self) -> list[str]:
        res = [self.vulnerability_id]
        for a in self.aliases:
            if a not in res:
                res.append(a)
        return res
