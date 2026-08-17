"""Abstract Base Manifest Parser Contract."""

from abc import ABC, abstractmethod
from python_hunter.domain.dependencies.models import Dependency, ManifestType, PackageManager


class BaseManifestParser(ABC):
    """Abstract base class for all dependency manifest parsers."""

    manifest_type: ManifestType
    package_manager: PackageManager

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """Check if parser handles given file path."""

    @abstractmethod
    def parse(self, file_path: str, content: str) -> list[Dependency]:
        """Parse manifest file content and return normalized Dependency objects."""
