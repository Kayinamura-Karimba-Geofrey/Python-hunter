"""PYH-GIT-005: Suspicious CI/CD Security Change Detector."""

import re
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import GitCommit, GitFileChange


class PYHGit005CICDSecurity:
    """Detector for dangerous shell command execution introduced in CI/CD workflow files."""

    id = "PYH-GIT-005"
    name = "Suspicious CI/CD Security Change"
    category = Category.GIT_RISK
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    DANGEROUS_PATTERNS = [
        (r"curl\s+.*\|\s*(bash|sh)", "Unsanitized remote script execution via curl | bash"),
        (r"wget\s+.*\|\s*(bash|sh)", "Unsanitized remote script execution via wget | sh"),
        (r"\beval\s+\$", "Dynamic evaluation of unquoted variable"),
    ]

    def evaluate_workflow_content(
        self, file_path: str, content: str, commit: GitCommit | None = None
    ) -> list[Finding]:
        if not file_path.startswith((".github/workflows", ".gitlab-ci", ".circleci")):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            for pattern, desc in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    loc = Location(line_start=idx, line_end=idx, column_start=0, column_end=len(line))
                    commit_str = f" in commit '{commit.commit_hash[:8]}'" if commit else ""
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Dangerous Command in CI/CD Workflow: {file_path}",
                            description=f"CI/CD workflow '{file_path}'{commit_str} contains suspicious command pattern: {desc}.",
                            file_path=file_path,
                            location=loc,
                            evidence=line.strip()[:100],
                            remediation="Avoid piping unverified remote scripts to shell interpreters. Download and audit scripts prior to execution.",
                        )
                    )

        return findings
