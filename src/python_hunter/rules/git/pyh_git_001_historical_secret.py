"""PYH-GIT-001: Historical Secret Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import SecretLifecycleRecord, SecretLifecycleStatus


class PYHGit001HistoricalSecret:
    """Detector for secrets introduced in Git repository history."""

    id = "PYH-GIT-001"
    name = "Historical Secret Detected"
    category = Category.SECRET_LEAK
    confidence = Confidence.HIGH

    def evaluate_record(self, record: SecretLifecycleRecord) -> Finding:
        is_removed = record.current_status == SecretLifecycleStatus.REMOVED_FROM_HEAD
        severity = Severity.HIGH if is_removed else Severity.CRITICAL

        status_str = "REMOVED FROM HEAD" if is_removed else "STILL PRESENT IN HEAD"
        exposure_str = f" Exposure Window: {record.exposure_days} days." if record.exposure_days > 0 else ""

        description = (
            f"Historical credential of type '{record.secret_type}' was detected in Git commit '{record.introduced_commit[:8]}'. "
            f"Current status: {status_str}.{exposure_str} "
            "Note: Removing a secret from latest HEAD does NOT remove it from Git history."
        )

        loc = Location(line_start=1, line_end=1, column_start=0, column_end=10)

        remediation = (
            "1. Treat the credential as exposed and immediately rotate/revoke it with the issuing service.\n"
            "2. Purge secret from Git history using BFG Repo-Cleaner or git-filter-repo if necessary."
        )

        return Finding(
            rule_id=self.id,
            severity=severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Historical Secret ({record.secret_type}): {record.file_path}",
            description=description,
            file_path=record.file_path,
            location=loc,
            evidence=f"Fingerprint: {record.secret_fingerprint[:12]} | Introduced: {record.introduced_commit[:8]} | Status: {record.current_status.value}",
            remediation=remediation,
        )
