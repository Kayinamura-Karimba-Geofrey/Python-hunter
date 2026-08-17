"""Package Provenance and Integrity Metadata Models."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DependencyProvenance:
    """Tracks origin, repository, registry, integrity, and manifest confidence."""

    registry: str = "PyPI"
    repository: str = ""
    source_url: str = ""
    version: str = ""
    revision: str = ""
    manifest_path: str = ""
    confidence: float = 1.0
    integrity_hashes: list[str] = field(default_factory=list)
    is_signed: bool = False
