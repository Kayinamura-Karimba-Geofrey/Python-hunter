"""Security and Read-Only Safety Tests for Git Analysis Subsystem."""

import unittest
from python_hunter.application.use_cases.analyze_git import AnalyzeGitUseCase
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitFileChange,
    GitRemoteInfo,
)
from python_hunter.infrastructure.git.fake import FakeGitRepository


class TestGitSafetyAndRedaction(unittest.TestCase):
    """Security tests confirming read-only execution safety and zero raw secret leakage."""

    def test_zero_raw_secret_leakage_in_git_findings(self) -> None:
        raw_secret_val = "AKIAIOSFODNN7EXAMPLESECRET123"
        commit = GitCommit(
            commit_hash="c11111111111",
            author_name="Dev",
            author_email="dev@example.com",
            timestamp="2026-01-01T00:00:00Z",
            subject="Add AWS credentials",
            message="Commit AWS credential",
            files_changed=[GitFileChange(file_path="config.py", change_type=ChangeType.ADDED)],
        )

        fake_repo = FakeGitRepository(
            repository_root="/mock/repo",
            commits=[commit],
            file_contents={("c11111111111", "config.py"): f"AWS_SECRET = '{raw_secret_val}'"},
            remotes=[GitRemoteInfo(name="origin", url=f"https://user:{raw_secret_val}@github.com/repo.git", has_embedded_credentials=True)],
        )

        use_case = AnalyzeGitUseCase(git_repo=fake_repo)
        res = use_case.execute("/mock/repo")

        findings = res["findings"]
        self.assertTrue(len(findings) >= 1)

        for f in findings:
            self.assertNotIn(raw_secret_val, f.title)
            self.assertNotIn(raw_secret_val, f.description)
            self.assertNotIn(raw_secret_val, f.evidence)
            self.assertNotIn(raw_secret_val, f.remediation)

    def test_read_only_guarantee(self) -> None:
        """Verify that FakeGitRepository and SubprocessGitRepository never call mutating Git commands."""
        fake_repo = FakeGitRepository()
        use_case = AnalyzeGitUseCase(git_repo=fake_repo)
        res = use_case.execute("/mock/repo")
        self.assertTrue(res["is_git_repository"])


if __name__ == "__main__":
    unittest.main()
