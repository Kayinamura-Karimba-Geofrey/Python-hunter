"""Unit tests for GitRepository Providers (SubprocessGitRepository and FakeGitRepository)."""

import os
import unittest
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitFileChange,
    GitHookInfo,
    GitRemoteInfo,
)
from python_hunter.infrastructure.git.fake import FakeGitRepository
from python_hunter.infrastructure.git.repository import SubprocessGitRepository


class TestGitRepositoryProviders(unittest.TestCase):
    """Test cases for Git abstraction implementations."""

    def test_fake_git_repository(self) -> None:
        commit1 = GitCommit(
            commit_hash="c111111",
            author_name="Dev",
            author_email="dev@example.com",
            timestamp="2026-01-01T00:00:00Z",
            subject="Initial commit",
            message="Init",
            files_changed=[GitFileChange(file_path=".env", change_type=ChangeType.ADDED)],
        )
        fake_repo = FakeGitRepository(
            repository_root="/mock/repo",
            commits=[commit1],
            remotes=[GitRemoteInfo(name="origin", url="https://user:pass@github.com/repo.git", has_embedded_credentials=True)],
            hooks=[GitHookInfo(name="pre-commit", path="/mock/repo/.git/hooks/pre-commit", is_active=True, is_suspicious=True, suspicious_reasons=["curl | bash"])],
        )

        self.assertTrue(fake_repo.is_valid_repository())
        self.assertEqual(fake_repo.get_repository_root(), "/mock/repo")
        commits = fake_repo.get_commits()
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0].commit_hash, "c111111")

        remotes = fake_repo.get_remotes()
        self.assertTrue(remotes[0].has_embedded_credentials)

        hooks = fake_repo.get_hooks()
        self.assertTrue(hooks[0].is_suspicious)

    def test_subprocess_git_repository_current_project(self) -> None:
        curr_dir = os.getcwd()
        repo = SubprocessGitRepository(curr_dir)
        self.assertTrue(repo.is_valid_repository())

        meta = repo.get_metadata()
        self.assertTrue(meta.total_commits > 0)
        self.assertTrue(len(meta.head_commit) >= 7)


if __name__ == "__main__":
    unittest.main()
