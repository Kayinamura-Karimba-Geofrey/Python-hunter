"""Unit tests for Git Security Rules PYH-GIT-001 through 008."""

import unittest
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitFileChange,
    GitHookInfo,
    GitRemoteInfo,
    SecretLifecycleRecord,
    SecretLifecycleStatus,
)
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


class TestGitSecurityRules(unittest.TestCase):
    """Test cases evaluating individual Git security rules."""

    def test_pyh_git_001_historical_secret(self) -> None:
        rule = PYHGit001HistoricalSecret()
        rec = SecretLifecycleRecord(
            secret_fingerprint="fp123",
            detector_id="PYH-SECRET-006",
            secret_type="AWS Credentials",
            file_path="config/aws.py",
            introduced_commit="abc12345",
            introduced_date="2026-01-01T00:00:00Z",
            removed_commit="def67890",
            removed_date="2026-01-03T00:00:00Z",
            current_status=SecretLifecycleStatus.REMOVED_FROM_HEAD,
            exposure_days=2,
        )
        finding = rule.evaluate_record(rec)
        self.assertEqual(finding.rule_id, "PYH-GIT-001")
        self.assertIn("Historical Secret", finding.title)

    def test_pyh_git_002_sensitive_file(self) -> None:
        rule = PYHGit002SensitiveFile()
        commit = GitCommit(
            commit_hash="c111", author_name="a", author_email="e", timestamp="t", subject="s", message="m"
        )
        change = GitFileChange(file_path=".env", change_type=ChangeType.ADDED)
        finding = rule.evaluate_change(commit, change)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "PYH-GIT-002")

    def test_pyh_git_003_gitignore_omission(self) -> None:
        rule = PYHGit003GitignoreOmission()
        findings = rule.evaluate_gitignore("build/\n__pycache__/\n")
        self.assertTrue(len(findings) >= 2)
        self.assertTrue(any(f.title.endswith(".env") for f in findings))

    def test_pyh_git_004_remote_credential(self) -> None:
        rule = PYHGit004RemoteCredential()
        remote = GitRemoteInfo(name="origin", url="https://user:password123@github.com/repo.git", has_embedded_credentials=True)
        finding = rule.evaluate_remote(remote)
        self.assertIsNotNone(finding)
        self.assertNotIn("password123", finding.evidence)  # Redacted!

    def test_pyh_git_005_cicd_security(self) -> None:
        rule = PYHGit005CICDSecurity()
        content = "name: CI\njobs:\n  build:\n    run: curl -s https://example.com/setup.sh | bash"
        findings = rule.evaluate_workflow_content(".github/workflows/main.yml", content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-GIT-005")

    def test_pyh_git_006_mutable_action_ref(self) -> None:
        rule = PYHGit006MutableActionRef()
        content = "steps:\n  - uses: actions/checkout@v2\n  - uses: thirdparty/action@main"
        findings = rule.evaluate_workflow_content(".github/workflows/main.yml", content)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "PYH-GIT-006")

    def test_pyh_git_007_git_hook_risk(self) -> None:
        rule = PYHGit007GitHookRisk()
        hook = GitHookInfo(name="pre-commit", path=".git/hooks/pre-commit", is_active=True, is_suspicious=True, suspicious_reasons=["Contains curl"])
        finding = rule.evaluate_hook(hook)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "PYH-GIT-007")

    def test_pyh_git_008_sensitive_config_change(self) -> None:
        rule = PYHGit008SensitiveConfigChange()
        commit = GitCommit(commit_hash="c111", author_name="a", author_email="e", timestamp="t", subject="s", message="m")
        diff = "+ DEBUG = True\n+ verify = False"
        findings = rule.evaluate_diff(diff, commit)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "PYH-GIT-008")


if __name__ == "__main__":
    unittest.main()
