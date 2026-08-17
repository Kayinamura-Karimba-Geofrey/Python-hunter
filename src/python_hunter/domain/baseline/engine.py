"""Baseline Snapshot and Scan Diff Engine."""

from datetime import datetime
import json
import logging
import os
from typing import Any

from python_hunter.domain.common.enums import FindingLifecycleState
from python_hunter.domain.findings.finding import Finding

logger = logging.getLogger(__name__)


class BaselineEngine:
    """Manages baseline snapshots, finding lifecycle state transitions, and scan diffing."""

    @staticmethod
    def create_baseline(findings: list[Finding], output_file: str) -> dict[str, Any]:
        """Create baseline JSON snapshot file."""
        baseline_data = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "count": len(findings),
            "fingerprints": [f.fingerprint for f in findings],
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "fingerprint": f.fingerprint,
                    "file_path": f.file_path,
                    "title": f.title,
                    "severity": f.severity.value,
                }
                for f in findings
            ],
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2)

        return baseline_data

    @staticmethod
    def apply_baseline(findings: list[Finding], baseline_data: dict[str, Any]) -> list[Finding]:
        """Update lifecycle_state of current findings based on baseline comparison."""
        prev_fps = set(baseline_data.get("fingerprints", []))
        prev_resolved_fps = set(baseline_data.get("resolved_fingerprints", []))

        for f in findings:
            if f.fingerprint in prev_fps:
                f.lifecycle_state = FindingLifecycleState.EXISTING
            elif f.fingerprint in prev_resolved_fps:
                f.lifecycle_state = FindingLifecycleState.REOPENED
            else:
                f.lifecycle_state = FindingLifecycleState.NEW

        return findings

    @staticmethod
    def diff_scans(old_data: dict[str, Any], new_data: dict[str, Any]) -> dict[str, Any]:
        """Calculate diff between two scan output dictionaries."""
        old_fps = {f["fingerprint"]: f for f in old_data.get("findings", [])}
        new_fps = {f["fingerprint"]: f for f in new_data.get("findings", [])}

        added = [f for fp, f in new_fps.items() if fp not in old_fps]
        removed = [f for fp, f in old_fps.items() if fp not in new_fps]
        unchanged = [f for fp, f in new_fps.items() if fp in old_fps]

        return {
            "added_count": len(added),
            "removed_count": len(removed),
            "unchanged_count": len(unchanged),
            "added_findings": added,
            "removed_findings": removed,
            "unchanged_findings": unchanged,
        }
