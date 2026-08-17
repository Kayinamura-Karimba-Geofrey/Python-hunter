"""FileSystem and Project Discovery Interfaces."""

from abc import ABC, abstractmethod
from typing import Iterator
from python_hunter.domain.discovery.manifest import FileMetadata, ProjectManifest


class FileSystem(ABC):
    """Abstract interface for filesystem access and safe path manipulation."""

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if path exists."""

    @abstractmethod
    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""

    @abstractmethod
    def is_file(self, path: str) -> bool:
        """Check if path is a regular file."""

    @abstractmethod
    def is_symlink(self, path: str) -> bool:
        """Check if path is a symbolic link."""

    @abstractmethod
    def normalize_path(self, path: str) -> str:
        """Return safe normalized path."""

    @abstractmethod
    def read_text_safe(self, path: str, max_bytes: int = 1_000_000) -> str:
        """Safely read text file content without loading huge files into memory."""

    @abstractmethod
    def walk(self, root_path: str, max_depth: int = 20) -> Iterator[tuple[str, list[str], list[str]]]:
        """Iterate safely through directory trees."""

    @abstractmethod
    def get_file_metadata(self, root_path: str, relative_path: str) -> FileMetadata:
        """Collect safe file metadata without following untrusted symlinks out of root."""


class ProjectDiscoveryEngine(ABC):
    """Abstract contract for Project Discovery Engine."""

    @abstractmethod
    def discover(self, target_path: str) -> ProjectManifest:
        """Discover, validate, classify, and construct ProjectManifest for target path."""
