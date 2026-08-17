"""PYH-GIT-002: Sensitive File Committed Detector."""

import os
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import GitCommit, GitFileChange


class PYHGit002SensitiveFile:
    """Detector for security-sensitive files committed to Git repository history."""

    id = "PYH-GIT-002"
    name = "Sensitive File Committed"
    category = Category.GIT_RISK
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    SENSITIVE_PATTERNS = {
        ".env", ".env.local", ".env.production", ".env.staging", ".env.dev",
        "credentials.json", "secrets.json", "id_rsa", "id_ed25519", "id_dsa",
    }
    SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".asc"}

    def evaluate_change(self, commit: GitCommit, change: GitFileChange) -> Finding | None:
        filename = os.path.basename(change.file_path).lower()
        ext = os.path.splitext(filename)[1].lower()

        is_sensitive = filename in self.SENSITIVE_PATTERNS or ext in self.SENSITIVE_EXTENSIONS
        if not is_sensitive:
            return None

        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(change.file_path))

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Sensitive File Committed: {change.file_path}",
            description=(
                f"Security-sensitive file '{change.file_path}' was committed in Git commit '{commit.commit_hash[:8]}'. "
                "Committing sensitive environment configurations or private key files risks unintended credential exposure."
            ),
            file_path=change.file_path,
            location=loc,
            evidence=f"Commit: {commit.commit_hash[:8]} | Action: {change.change_type.value} | Path: {change.file_path}",
            remediation="Remove sensitive file from Git repository, add path to .gitignore, and rotate any contained credentials.",
        )
