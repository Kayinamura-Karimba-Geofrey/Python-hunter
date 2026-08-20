"""Git History Secret Scanner and Pull Request Secret Diffing Engine."""

from dataclasses import dataclass, field
from enum import Enum
import os
import subprocess
from typing import Any, Dict, List, Optional, Set

from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.domain.secrets.models import (
    ExposureType,
    SecretCandidate,
    SecretExposure,
    compute_secret_fingerprint,
)
from python_hunter.domain.secrets.redaction import Redactor


@dataclass
class HistoricalSecretFinding:
    fingerprint: str
    secret_type: str
    detector_id: str
    first_seen_commit: str
    first_seen_author: str
    first_seen_date: str
    file_path: str
    is_deleted_in_head: bool
    current_status: str  # ACTIVE, DELETED_IN_GIT, ROTATED
    locations: List[Dict[str, Any]] = field(default_factory=list)


class GitHistorySecretScanner:
    """Scans repository Git commit history to discover historical and deleted secret exposures."""

    def __init__(self, engine: Optional[SecretDetectionEngine] = None) -> None:
        self.engine = engine or SecretDetectionEngine()

    def scan_git_history(
        self, repo_path: str, max_commits: int = 100
    ) -> List[HistoricalSecretFinding]:
        """Scans recent Git commit log diffs for credential leaks."""
        if not os.path.exists(os.path.join(repo_path, ".git")):
            return []

        historical_findings: Dict[str, HistoricalSecretFinding] = {}

        try:
            cmd = [
                "git",
                "-C",
                repo_path,
                "log",
                f"-n{max_commits}",
                "-p",
                "--date=iso",
                "--pretty=format:COMMIT_START|%H|%an|%ad",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            )
            output = result.stdout or ""

            current_commit = ""
            current_author = ""
            current_date = ""
            current_file = ""

            for line in output.splitlines():
                if line.startswith("COMMIT_START|"):
                    parts = line.split("|")
                    if len(parts) >= 4:
                        current_commit = parts[1]
                        current_author = parts[2]
                        current_date = parts[3]
                elif line.startswith("+++ b/"):
                    current_file = line[6:]
                elif line.startswith("+") and not line.startswith("+++"):
                    added_code = line[1:]
                    if not added_code.strip() or not self.engine.is_eligible_file(current_file):
                        continue

                    # Scan added diff line for candidates
                    for detector in self.engine.registry.enabled_detectors():
                        try:
                            candidates = detector.detect(added_code, current_file, None)  # type: ignore
                            for cand in candidates:
                                fp = cand.fingerprint or compute_secret_fingerprint(cand.value)
                                if fp not in historical_findings:
                                    historical_findings[fp] = HistoricalSecretFinding(
                                        fingerprint=fp,
                                        secret_type=cand.secret_type.value,
                                        detector_id=cand.detector_id,
                                        first_seen_commit=current_commit,
                                        first_seen_author=Redactor.sanitize_log_message(current_author),
                                        first_seen_date=current_date,
                                        file_path=current_file,
                                        is_deleted_in_head=True,  # Default to historical/deleted until verified in HEAD
                                        current_status="HISTORICAL_EXPOSURE",
                                    )
                                historical_findings[fp].locations.append({
                                    "commit": current_commit,
                                    "file": current_file,
                                    "author": Redactor.sanitize_log_message(current_author),
                                    "date": current_date,
                                })
                        except Exception:
                            continue
        except Exception:
            pass

        return list(historical_findings.values())


class PRSecretDiffEngine:
    """Detects secrets introduced, modified, or removed in Pull Requests."""

    @staticmethod
    def compare_secret_candidates(
        base_fingerprints: Set[str], head_candidates: List[SecretCandidate]
    ) -> Dict[str, Any]:
        introduced = []
        existing = []

        for cand in head_candidates:
            fp = cand.fingerprint
            if fp not in base_fingerprints:
                introduced.append(cand)
            else:
                existing.append(cand)

        return {
            "has_introduced_secrets": len(introduced) > 0,
            "introduced_count": len(introduced),
            "existing_count": len(existing),
            "introduced_candidates": introduced,
        }
