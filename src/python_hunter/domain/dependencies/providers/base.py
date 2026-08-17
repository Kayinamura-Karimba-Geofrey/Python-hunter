"""Abstract Package Metadata Provider Contract."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PackageMetadata:
    """Metadata response for a package."""

    name: str
    latest_version: str = ""
    release_history: list[str] = field(default_factory=list)
    yanked_versions: dict[str, str] = field(default_factory=dict)
    homepage: str = ""
    repository_url: str = ""
    license: str = ""
    summary: str = ""
    author: str = ""


class PackageMetadataProvider(ABC):
    """Abstract interface for package metadata lookups."""

    @abstractmethod
    def get_metadata(self, package_name: str) -> PackageMetadata | None:
        """Fetch package metadata by name."""
