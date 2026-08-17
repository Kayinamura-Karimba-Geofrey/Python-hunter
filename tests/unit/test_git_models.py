"""Unit tests for Git Domain Models and Data Structures."""

import unittest
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitFileChange,
    GitHookInfo,
    GitRemoteInfo,
    GitRepositoryMetadata,
    HistoryCompleteness,
    SecretLifecycleRecord,
    SecretLifecycleStatus,
)


class TestGitDomainModels(unittest.TestCase):
    """Test cases for Git domain entities, value objects, and lifecycle records."""

    def test_git_file_change_creation(self) -> None:
        change = GitFileChange(file_path="config/settings.py", change_type=ChangeType.MODIFIED)
        self.assertEqual(change.file_path, "config/settings.py")
        self.assertEqual(change.change_type, ChangeType.MODIFIED)

    def test_git_commit_creation(self) -> None:
        commit = GitCommit(
            commit_hash="abc123456789",
            author_name="Security Auditor",
            author_email="auditor@example.com",
            timestamp="2026-03-15T10:00:00Z",
            subject="Add secrets",
            message="Committing AWS keys for testing",
            parents=["000000000000"],
            files_changed=[GitFileChange(file_path=".env", change_type=ChangeType.ADDED)],
        )
        self.assertEqual(commit.commit_hash, "abc123456789")
        self.assertEqual(len(commit.files_changed), 1)

    def test_secret_lifecycle_record(self) -> None:
        rec = SecretLifecycleRecord(
            secret_fingerprint="sha256_mock_fp",
            detector_id="PYH-SECRET-006",
            secret_type="AWS Credentials",
            file_path="config/aws.py",
            introduced_commit="commit1",
            introduced_date="2026-01-01T00:00:00Z",
            removed_commit="commit2",
            removed_date="2026-01-05T00:00:00Z",
            current_status=SecretLifecycleStatus.REMOVED_FROM_HEAD,
            exposure_days=4,
        )
        self.assertEqual(rec.current_status, SecretLifecycleStatus.REMOVED_FROM_HEAD)
        self.assertEqual(rec.exposure_days, 4)

    def test_git_repository_metadata(self) -> None:
        meta = GitRepositoryMetadata(
            repository_root="/repo",
            head_commit="head123",
            branches=["main", "feature"],
            completeness=HistoryCompleteness.COMPLETE,
        )
        self.assertFalse(meta.is_shallow)
        self.assertEqual(meta.completeness, HistoryCompleteness.COMPLETE)


if __name__ == "__main__":
    unittest.main()
