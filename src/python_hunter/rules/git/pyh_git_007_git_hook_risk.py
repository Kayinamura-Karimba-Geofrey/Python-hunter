"""PYH-GIT-007: Suspicious Git Hook Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import GitHookInfo


class PYHGit007GitHookRisk:
    """Detector for suspicious or unauthorized local Git hooks."""

    id = "PYH-GIT-007"
    name = "Suspicious Git Hook"
    category = Category.GIT_RISK
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate_hook(self, hook: GitHookInfo) -> Finding | None:
        if not hook.is_suspicious:
            return None

        reasons_str = "; ".join(hook.suspicious_reasons)
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(hook.name))

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Suspicious Git Hook: {hook.name}",
            description=(
                f"Local Git hook '{hook.name}' at '{hook.path}' contains suspicious execution patterns: {reasons_str}. "
                "Malicious Git hooks can execute unauthorized background commands upon git operations."
            ),
            file_path=hook.path,
            location=loc,
            evidence=f"Hook: {hook.name} | Active: {hook.is_active} | Reasons: {reasons_str}",
            remediation="Audit Git hook file content, remove unauthorized shell commands, or disable executable permissions.",
        )
