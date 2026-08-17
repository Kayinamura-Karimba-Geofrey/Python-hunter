"""Git Security & Repository Domain Models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeType(str, Enum):
    """Git commit file change type."""

    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    RENAMED = "RENAMED"
    UNKNOWN = "UNKNOWN"


class SecretLifecycleStatus(str, Enum):
    """Status of a secret identified in Git history."""

    STILL_PRESENT = "STILL_PRESENT"
    REMOVED_FROM_HEAD = "REMOVED_FROM_HEAD"
    MODIFIED = "MODIFIED"
    UNKNOWN = "UNKNOWN"


class HistoryCompleteness(str, Enum):
    """Completeness of historical commit graph scanning."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class GitFileChange:
    """Represents a single file modification within a Git commit."""

    file_path: str
    change_type: ChangeType
    old_path: str = ""
    insertions: int = 0
    deletions: int = 0


@dataclass
class GitCommit:
    """Normalized representation of a single Git commit."""

    commit_hash: str
    author_name: str
    author_email: str
    timestamp: str
    subject: str
    message: str
    parents: list[str] = field(default_factory=list)
    files_changed: list[GitFileChange] = field(default_factory=list)
    insertions: int = 0
    deletions: int = 0


@dataclass
class SecretLifecycleRecord:
    """Tracks introduction, modification, and removal lifecycle of a secret in Git history."""

    secret_fingerprint: str
    detector_id: str
    secret_type: str
    file_path: str
    introduced_commit: str
    introduced_date: str
    removed_commit: str = ""
    removed_date: str = ""
    current_status: SecretLifecycleStatus = SecretLifecycleStatus.STILL_PRESENT
    exposure_days: int = 0


@dataclass
class GitRemoteInfo:
    """Git remote configuration record."""

    name: str
    url: str
    has_embedded_credentials: bool = False


@dataclass
class GitHookInfo:
    """Git repository hook inspection record."""

    name: str
    path: str
    is_active: bool = False
    is_suspicious: bool = False
    suspicious_reasons: list[str] = field(default_factory=list)


@dataclass
class GitRepositoryMetadata:
    """Comprehensive security-relevant metadata of a scanned Git repository."""

    repository_root: str
    head_commit: str = ""
    default_branch: str = "main"
    branches: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    total_commits: int = 0
    is_shallow: bool = False
    completeness: HistoryCompleteness = HistoryCompleteness.COMPLETE
    remotes: list[GitRemoteInfo] = field(default_factory=list)
    hooks: list[GitHookInfo] = field(default_factory=list)
