"""PYH-GIT-008: Security-Sensitive Configuration Change Detector."""

import re
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import GitCommit


class PYHGit008SensitiveConfigChange:
    """Detector for security-sensitive configuration changes introduced in commit diffs."""

    id = "PYH-GIT-008"
    name = "Security-Sensitive Configuration Change"
    category = Category.GIT_RISK
    severity = Severity.INFO
    confidence = Confidence.MEDIUM

    SENSITIVE_DIFF_PATTERNS = [
        (r"\+\s*DEBUG\s*=\s*True", "DEBUG mode enabled in production code"),
        (r"\+\s*verify\s*=\s*False", "SSL certificate verification disabled (verify=False)"),
        (r"\+\s*ssl_verify\s*=\s*False", "SSL certificate verification disabled"),
        (r"\+\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True", "Permissive CORS configuration allowing all origins"),
        (r"\+\s*allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]", "Permissive CORS wildcard origin configuration"),
    ]

    def evaluate_diff(self, diff_content: str, commit: GitCommit) -> list[Finding]:
        if not diff_content:
            return []

        findings: list[Finding] = []
        lines = diff_content.splitlines()

        for idx, line in enumerate(lines, start=1):
            for pattern, desc in self.SENSITIVE_DIFF_PATTERNS:
                if re.search(pattern, line):
                    loc = Location(line_start=idx, line_end=idx, column_start=0, column_end=len(line))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Sensitive Config Change in Commit '{commit.commit_hash[:8]}'",
                            description=f"Commit '{commit.commit_hash[:8]}' introduced security-sensitive configuration: {desc}.",
                            file_path=f"commit:{commit.commit_hash[:8]}",
                            location=loc,
                            evidence=line.strip()[:100],
                            remediation="Verify whether debug/permissive flags were introduced intentionally and restrict them in production environments.",
                        )
                    )

        return findings
