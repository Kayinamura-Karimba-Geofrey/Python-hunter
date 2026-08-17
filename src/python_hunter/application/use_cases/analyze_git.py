"""Application Use Case for Git Repository & History Security Analysis."""

from datetime import datetime, timezone
import os
from typing import Any

from python_hunter.detectors.secrets import create_default_secret_registry
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Category, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.interfaces import GitRepository
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitRepositoryMetadata,
    HistoryCompleteness,
    SecretLifecycleRecord,
    SecretLifecycleStatus,
)
from python_hunter.domain.projects.project import Project
from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.infrastructure.git.repository import SubprocessGitRepository
from python_hunter.rules.git import (
    PYHGit001HistoricalSecret,
    PYHGit002SensitiveFile,
    PYHGit003GitignoreOmission,
    PYHGit004RemoteCredential,
    PYHGit005CICDSecurity,
    PYHGit006MutableActionRef,
    PYHGit007GitHookRisk,
    PYHGit008SensitiveConfigChange,
)


class AnalyzeGitUseCase:
    """Orchestrates Git repository discovery, commit traversal, historical secret scanning, lifecycle tracking, and rule evaluation."""

    def __init__(
        self,
        git_repo: GitRepository | None = None,
        secret_engine: SecretDetectionEngine | None = None,
    ) -> None:
        self.git_repo = git_repo
        self.secret_engine = secret_engine or SecretDetectionEngine(registry=create_default_secret_registry())

        # Instantiate Git security rules
        self.rule_001 = PYHGit001HistoricalSecret()
        self.rule_002 = PYHGit002SensitiveFile()
        self.rule_003 = PYHGit003GitignoreOmission()
        self.rule_004 = PYHGit004RemoteCredential()
        self.rule_005 = PYHGit005CICDSecurity()
        self.rule_006 = PYHGit006MutableActionRef()
        self.rule_007 = PYHGit007GitHookRisk()
        self.rule_008 = PYHGit008SensitiveConfigChange()

    def execute(
        self,
        target_path: str,
        max_commits: int | None = 500,
        since: str | None = None,
        path_filter: str | None = None,
    ) -> dict[str, Any]:
        """Execute Git security analysis on target project repository."""
        repo = self.git_repo or SubprocessGitRepository(target_path)

        if not repo.is_valid_repository():
            return {
                "is_git_repository": False,
                "repository_root": target_path,
                "metadata": None,
                "commits_analyzed": 0,
                "findings": [],
                "secret_records": [],
            }

        metadata = repo.get_metadata()
        commits = repo.get_commits(max_count=max_commits, since=since, path_filter=path_filter)

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        # 1. Evaluate Remotes (PYH-GIT-004)
        for remote in metadata.remotes:
            f = self.rule_004.evaluate_remote(remote)
            if f and f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                findings.append(f)

        # 2. Evaluate Hooks (PYH-GIT-007)
        for hook in metadata.hooks:
            f = self.rule_007.evaluate_hook(hook)
            if f and f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                findings.append(f)

        # 3. Evaluate .gitignore (PYH-GIT-003)
        root = metadata.repository_root
        gitignore_path = os.path.join(root, ".gitignore")
        if os.path.exists(gitignore_path) and os.path.isfile(gitignore_path):
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="replace") as gf:
                    g_content = gf.read()
                gi_findings = self.rule_003.evaluate_gitignore(g_content)
                for f in gi_findings:
                    if f.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(f.fingerprint)
                        findings.append(f)
            except Exception:
                pass

        # 4. Commit Traversal & Historical Secret Lifecycle Analysis
        dummy_project = Project(name=os.path.basename(root) or "git_repo", root_path=root)
        analysis_ctx = AnalysisContext(scan_id="git_scan", project=dummy_project, target_files=[])

        # Fingerprint -> SecretLifecycleRecord
        secret_lifecycle_map: dict[str, SecretLifecycleRecord] = {}
        # Keep track of secrets present in HEAD
        head_commit_hash = metadata.head_commit

        for commit in reversed(commits):  # Process oldest to newest
            # Evaluate PYH-GIT-002 (Sensitive File Committed)
            for change in commit.files_changed:
                if change.change_type != ChangeType.DELETED:
                    f = self.rule_002.evaluate_change(commit, change)
                    if f and f.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(f.fingerprint)
                        findings.append(f)

                # Scan file content at commit for historical secrets
                if change.change_type in (ChangeType.ADDED, ChangeType.MODIFIED):
                    content = repo.get_file_content_at_commit(commit.commit_hash, change.file_path)
                    if content and SecretDetectionEngine.is_eligible_file(change.file_path):
                        secret_findings = self.secret_engine.scan_file(change.file_path, content, analysis_ctx)
                        for sf in secret_findings:
                            sp_fp = sf.fingerprint
                            if sp_fp not in secret_lifecycle_map:
                                secret_lifecycle_map[sp_fp] = SecretLifecycleRecord(
                                    secret_fingerprint=sp_fp,
                                    detector_id=sf.rule_id,
                                    secret_type=sf.rule_id,
                                    file_path=change.file_path,
                                    introduced_commit=commit.commit_hash,
                                    introduced_date=commit.timestamp,
                                    current_status=SecretLifecycleStatus.STILL_PRESENT,
                                )

                # Check if file deletion removed secret
                elif change.change_type == ChangeType.DELETED:
                    for fp, record in secret_lifecycle_map.items():
                        if record.file_path == change.file_path and record.current_status == SecretLifecycleStatus.STILL_PRESENT:
                            record.removed_commit = commit.commit_hash
                            record.removed_date = commit.timestamp
                            record.current_status = SecretLifecycleStatus.REMOVED_FROM_HEAD

            # Evaluate Workflow files (PYH-GIT-005 & PYH-GIT-006)
            for change in commit.files_changed:
                if change.file_path.startswith(".github/workflows") and change.change_type != ChangeType.DELETED:
                    wf_content = repo.get_file_content_at_commit(commit.commit_hash, change.file_path)
                    if wf_content:
                        for f in self.rule_005.evaluate_workflow_content(change.file_path, wf_content, commit):
                            if f.fingerprint not in seen_fingerprints:
                                seen_fingerprints.add(f.fingerprint)
                                findings.append(f)
                        for f in self.rule_006.evaluate_workflow_content(change.file_path, wf_content):
                            if f.fingerprint not in seen_fingerprints:
                                seen_fingerprints.add(f.fingerprint)
                                findings.append(f)

            # Evaluate Diff Config Changes (PYH-GIT-008)
            diff_text = repo.get_diff(commit.commit_hash)
            if diff_text:
                for f in self.rule_008.evaluate_diff(diff_text, commit):
                    if f.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(f.fingerprint)
                        findings.append(f)

        # Check if secrets in secret_lifecycle_map are present in latest HEAD
        if head_commit_hash:
            for fp, record in secret_lifecycle_map.items():
                head_content = repo.get_file_content_at_commit(head_commit_hash, record.file_path)
                if not head_content:
                    record.current_status = SecretLifecycleStatus.REMOVED_FROM_HEAD
                else:
                    head_sfs = self.secret_engine.scan_file(record.file_path, head_content, analysis_ctx)
                    if not any(hsf.fingerprint == fp for hsf in head_sfs):
                        record.current_status = SecretLifecycleStatus.REMOVED_FROM_HEAD

        # Calculate exposure days and generate PYH-GIT-001 findings
        secret_records = list(secret_lifecycle_map.values())
        for record in secret_records:
            if record.introduced_date and record.removed_date:
                try:
                    d_intro = datetime.fromisoformat(record.introduced_date)
                    d_rem = datetime.fromisoformat(record.removed_date)
                    record.exposure_days = max(0, (d_rem - d_intro).days)
                except Exception:
                    record.exposure_days = 0

            # Generate PYH-GIT-001 finding for historical secret
            f = self.rule_001.evaluate_record(record)
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                findings.append(f)

        # Summarize counts
        current_secrets_count = sum(1 for r in secret_records if r.current_status == SecretLifecycleStatus.STILL_PRESENT)
        removed_secrets_count = sum(1 for r in secret_records if r.current_status == SecretLifecycleStatus.REMOVED_FROM_HEAD)

        summary_counts = {
            "total_historical_secrets": len(secret_records),
            "secrets_still_present": current_secrets_count,
            "secrets_removed": removed_secrets_count,
            "git_findings_count": len(findings),
        }

        return {
            "is_git_repository": True,
            "repository_root": metadata.repository_root,
            "metadata": metadata,
            "commits_analyzed": len(commits),
            "summary_counts": summary_counts,
            "secret_records": secret_records,
            "findings": findings,
        }
