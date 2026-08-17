"""PYH-GIT-004: Credential Embedded in Git Remote URL Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import GitRemoteInfo
from python_hunter.domain.secrets.redaction import Redactor


class PYHGit004RemoteCredential:
    """Detector for authentication credentials embedded in Git remote configuration URLs."""

    id = "PYH-GIT-004"
    name = "Credential Embedded in Git Remote"
    category = Category.GIT_RISK
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate_remote(self, remote: GitRemoteInfo, git_config_path: str = ".git/config") -> Finding | None:
        if not remote.has_embedded_credentials:
            return None

        # Redact remote URL to guarantee zero secret leakage
        sanitized_url = Redactor.redact_value(remote.url)
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(remote.name))

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Credential Embedded in Git Remote '{remote.name}'",
            description=(
                f"Git remote '{remote.name}' URL contains embedded plaintext authentication credentials. "
                "Plaintext credentials in Git configuration risk exposure in log files and shell history."
            ),
            file_path=git_config_path,
            location=loc,
            evidence=f"Remote: {remote.name} | URL: {sanitized_url}",
            remediation="Remove embedded username/password from remote URL and use SSH keys or credential helpers.",
        )
