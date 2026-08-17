"""Git Repository Provider Interface Abstraction."""

from abc import ABC, abstractmethod
from typing import Any

from python_hunter.domain.git.models import (
    GitCommit,
    GitHookInfo,
    GitRemoteInfo,
    GitRepositoryMetadata,
)


class GitRepository(ABC):
    """Abstract Base Class providing read-only access to Git repository history and metadata."""

    @abstractmethod
    def is_valid_repository(self) -> bool:
        """Check if target path is a valid Git repository."""
        pass

    @abstractmethod
    def get_repository_root(self) -> str:
        """Get absolute path to repository root."""
        pass

    @abstractmethod
    def get_metadata(self) -> GitRepositoryMetadata:
        """Retrieve repository metadata including branches, tags, and remotes."""
        pass

    @abstractmethod
    def get_commits(
        self,
        max_count: int | None = None,
        since: str | None = None,
        path_filter: str | None = None,
    ) -> list[GitCommit]:
        """Fetch list of commits matching query parameters."""
        pass

    @abstractmethod
    def get_commit(self, commit_hash: str) -> GitCommit | None:
        """Fetch details of a single commit."""
        pass

    @abstractmethod
    def get_file_content_at_commit(self, commit_hash: str, file_path: str) -> str | None:
        """Retrieve read-only text content of a file at a specific commit revision."""
        pass

    @abstractmethod
    def get_diff(self, commit_hash: str) -> str:
        """Retrieve unified diff for a commit."""
        pass

    @abstractmethod
    def get_remotes(self) -> list[GitRemoteInfo]:
        """Inspect repository remotes."""
        pass

    @abstractmethod
    def get_hooks(self) -> list[GitHookInfo]:
        """Inspect repository hooks statically without executing them."""
        pass
