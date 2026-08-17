"""PYH-GIT-006: Mutable GitHub Action Reference Detector."""

import re
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding


class PYHGit006MutableActionRef:
    """Detector for third-party GitHub Actions referenced by mutable tags instead of full commit SHA hashes."""

    id = "PYH-GIT-006"
    name = "Mutable GitHub Action Reference"
    category = Category.SUPPLY_CHAIN
    severity = Severity.LOW
    confidence = Confidence.HIGH

    # Matches uses: owner/repo@v1 or uses: owner/repo@main (not a 40-char SHA)
    USES_REGEX = re.compile(r"uses:\s*([a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)@([a-zA-Z0-9_.-]+)")

    def evaluate_workflow_content(self, file_path: str, content: str) -> list[Finding]:
        if not file_path.startswith(".github/workflows"):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            match = self.USES_REGEX.search(line)
            if match:
                action_name = match.group(1)
                ref = match.group(2)
                # Ignore official actions or full 40-char SHA hashes
                is_sha = len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref)
                if not is_sha:
                    loc = Location(line_start=idx, line_end=idx, column_start=0, column_end=len(line))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Mutable GitHub Action Ref: {action_name}@{ref}",
                            description=(
                                f"GitHub Action '{action_name}' in '{file_path}' uses mutable reference '@{ref}'. "
                                "Mutable tags risk supply-chain compromise if action repository tags are modified or hijacked."
                            ),
                            file_path=file_path,
                            location=loc,
                            evidence=f"uses: {action_name}@{ref}",
                            remediation=f"Pin third-party GitHub Action '{action_name}' to an explicit 40-character commit SHA hash.",
                        )
                    )

        return findings
