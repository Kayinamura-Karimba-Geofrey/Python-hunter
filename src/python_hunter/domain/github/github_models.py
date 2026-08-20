"""Domain models for GitHub Integration and Pull Request Security Platform."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class GitHubPermission(str, Enum):
    """Minimum GitHub App permissions required with documentation of rationale."""

    REPOSITORY_METADATA = "repository_metadata"  # Read repository metadata and structure
    CONTENTS = "contents"  # Read repository source code for static security analysis
    PULL_REQUESTS = "pull_requests"  # Read PR details, head/base commits, changed files
    CHECKS = "checks"  # Create and update GitHub Check Runs with PASS/WARN/FAIL results
    COMMIT_STATUSES = "commit_statuses"  # Optional commit status reporting
    ISSUES_COMMENTS = "issues_comments"  # Create and update security summary PR comments
    WEBHOOKS = "webhooks"  # Receive webhook push and pull_request events


class GitHubInstallationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class PullRequestStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    MERGED = "MERGED"


class PolicyResultStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class GitHubInstallation:
    """Represents a GitHub App installation for an organization or user account."""

    installation_id: str
    organization: str
    repositories: List[str] = field(default_factory=list)
    permissions: List[GitHubPermission] = field(default_factory=list)
    status: GitHubInstallationStatus = GitHubInstallationStatus.ACTIVE
    installed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GitHubRepository:
    """Represents a repository monitored by Python Hunter."""

    id: str
    full_name: str
    installation_id: str
    default_branch: str = "main"
    is_private: bool = True
    html_url: str = ""
    clone_url: str = ""


@dataclass
class GitHubPullRequest:
    """Represents a GitHub Pull Request being analyzed."""

    pr_id: str
    number: int
    title: str
    author: str
    repository: str
    base_branch: str
    base_sha: str
    head_branch: str
    head_sha: str
    status: PullRequestStatus = PullRequestStatus.OPEN
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GitHubAnnotation:
    """Inline code annotation for a GitHub Check Run."""

    path: str
    start_line: int
    end_line: int
    annotation_level: str  # "notice", "warning", "failure"
    title: str
    message: str
    raw_details: Optional[str] = None


@dataclass
class GitHubCheckRun:
    """Payload representation of a GitHub Check Run."""

    name: str = "Python Hunter Security Analysis"
    head_sha: str = ""
    status: str = "completed"  # "queued", "in_progress", "completed"
    conclusion: str = "neutral"  # "success", "failure", "neutral", "action_required"
    summary: str = ""
    text: str = ""
    annotations: List[GitHubAnnotation] = field(default_factory=list)


@dataclass
class PullRequestSecurityResult:
    """Complete security assessment result for a PR comparison (BASE vs HEAD)."""

    pr_number: int
    repository: str
    base_sha: str
    head_sha: str
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    reopened_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    fixed_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    dependency_regressions: List[Dict[str, Any]] = field(default_factory=list)
    secret_regressions: List[Dict[str, Any]] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    security_relevant_files: List[str] = field(default_factory=list)
    risk_delta: float = 0.0
    score_delta: int = 0
    base_score: int = 100
    head_score: int = 100
    risk_classification: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    policy_result: PolicyResultStatus = PolicyResultStatus.PASS
    policy_violations: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PullRequestSecuritySummary:
    """Machine-readable summary consumable by API, CLI, Dashboard, Check Run, CI/CD."""

    pr_id: str
    pr_number: int
    repository: str
    title: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str
    status: str
    security_score: int
    score_delta: int
    risk_level: str
    policy_result: PolicyResultStatus
    new_vulnerabilities_count: int
    fixed_vulnerabilities_count: int
    new_attack_paths_count: int
    dependency_regressions_count: int
    secrets_found_count: int
    summary_markdown: str


@dataclass
class GitHubWebhookDelivery:
    """Tracks processed webhook delivery IDs for replay attack prevention."""

    delivery_id: str
    event_type: str
    processed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "SUCCESS"
