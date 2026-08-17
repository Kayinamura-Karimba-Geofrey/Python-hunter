"""PYH-GIT-003: Sensitive File Not Ignored Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding


class PYHGit003GitignoreOmission:
    """Detector for missing security-sensitive ignore rules in .gitignore."""

    id = "PYH-GIT-003"
    name = "Sensitive File Not Ignored"
    category = Category.GIT_RISK
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    RECOMMENDED_IGNORES = [
        (".env", ".env files containing environment secrets"),
        ("*.pem", "Private key PEM files"),
        ("*.key", "Private key files"),
        ("credentials*.json", "Service account credentials files"),
    ]

    def evaluate_gitignore(self, gitignore_content: str, gitignore_path: str = ".gitignore") -> list[Finding]:
        findings: list[Finding] = []
        lines = [line.strip() for line in gitignore_content.splitlines() if line.strip() and not line.strip().startswith("#")]

        for pattern, desc in self.RECOMMENDED_IGNORES:
            pattern_matched = any(pattern == line or pattern in line for line in lines)
            if not pattern_matched:
                loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(pattern))
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=f"Missing .gitignore Pattern: {pattern}",
                        description=f".gitignore file is missing recommended security pattern '{pattern}' ({desc}).",
                        file_path=gitignore_path,
                        location=loc,
                        evidence=f"Missing Pattern: {pattern}",
                        remediation=f"Add '{pattern}' to .gitignore file to prevent accidental secret commits.",
                    )
                )

        return findings
