"""Project Discovery domain contracts and models."""

from python_hunter.domain.discovery.enums import (
    DirectoryCategory,
    FileCategory,
    PackageLayout,
    ProjectType,
)
from python_hunter.domain.discovery.interfaces import FileSystem, ProjectDiscoveryEngine
from python_hunter.domain.discovery.manifest import (
    DirectoryMetadata,
    FileMetadata,
    ManifestStatistics,
    ProjectManifest,
)

__all__ = [
    "ProjectType",
    "PackageLayout",
    "FileCategory",
    "DirectoryCategory",
    "FileMetadata",
    "DirectoryMetadata",
    "ManifestStatistics",
    "ProjectManifest",
    "FileSystem",
    "ProjectDiscoveryEngine",
]
