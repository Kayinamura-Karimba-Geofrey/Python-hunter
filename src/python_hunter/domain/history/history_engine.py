"""History Store and Snapshot Comparator Engine."""

from datetime import datetime
import hashlib
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.history.history_models import (
    FindingLifecycle,
    RegressionType,
    SecurityRegression,
    SecuritySnapshot,
    SnapshotComparison,
)


class SecurityHistoryStore:
    """In-memory and local file snapshot persistence engine."""

    def __init__(self) -> None:
        self._snapshots: dict[str, SecuritySnapshot] = {}

    def save_snapshot(self, snapshot: SecuritySnapshot) -> None:
        self._snapshots[snapshot.commit_sha] = snapshot

    def get_snapshot(self, commit_sha: str) -> SecuritySnapshot | None:
        return self._snapshots.get(commit_sha)


class SnapshotComparator:
    """Compares snapshots, computes deterministic fingerprints, tracks finding lifecycles, and flags regressions."""

    @staticmethod
    def compute_fingerprint(finding: Finding) -> str:
        """Compute stable deterministic finding fingerprint ignoring line movement."""
        raw = f"{finding.rule_id}:{finding.file_path}:{finding.title}:{finding.evidence}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def compare(self, previous: SecuritySnapshot, current: SecuritySnapshot) -> SnapshotComparison:
        prev_map = {self.compute_fingerprint(f): f for f in previous.findings}
        curr_map = {self.compute_fingerprint(f): f for f in current.findings}

        new_fps = set(curr_map.keys()) - set(prev_map.keys())
        fixed_fps = set(prev_map.keys()) - set(curr_map.keys())
        existing_fps = set(curr_map.keys()).intersection(set(prev_map.keys()))

        new_findings = [curr_map[fp] for fp in new_fps]
        fixed_findings = [prev_map[fp] for fp in fixed_fps]
        existing_findings = [curr_map[fp] for fp in existing_fps]

        regressions = []
        for f in new_findings:
            regressions.append(
                SecurityRegression(
                    regression_id=f"REG-{f.rule_id}",
                    regression_type=RegressionType.NEW_VULNERABILITY,
                    severity=f.severity,
                    description=f"New vulnerability introduced: {f.title} in {f.file_path}",
                )
            )

        risk_delta = current.risk_score - previous.risk_score
        score_delta = current.security_score - previous.security_score

        trend = "stable"
        if score_delta > 1.0:
            trend = "improving"
        elif score_delta < -1.0:
            trend = "degrading"

        return SnapshotComparison(
            previous_commit=previous.commit_sha,
            current_commit=current.commit_sha,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            existing_findings=existing_findings,
            regressions=regressions,
            risk_delta=risk_delta,
            security_score_delta=score_delta,
            trend=trend,
        )
