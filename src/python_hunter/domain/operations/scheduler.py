"""Security Scheduler for periodic scans, intelligence refresh, and posture tracking."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class MonitoringMode(str, Enum):
    """Monitoring operation modes."""

    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    EVENT_DRIVEN = "EVENT_DRIVEN"
    CONTINUOUS = "CONTINUOUS"


@dataclass
class MonitoredRepository:
    """Registration record for continuous security monitoring."""

    repository: str
    branch: str = "main"
    monitoring_mode: MonitoringMode = MonitoringMode.CONTINUOUS
    scan_frequency_minutes: int = 60
    last_scan_at: datetime | None = None
    is_paused: bool = False


class SecurityScheduler:
    """Scheduler for cron-like periodic analysis, posture snapshots, and intelligence refreshes."""

    def __init__(self) -> None:
        self.monitored_repos: dict[str, MonitoredRepository] = {}
        self.tasks: list[dict[str, Any]] = []

    def register_repository(self, repo: MonitoredRepository) -> None:
        self.monitored_repos[repo.repository] = repo

    def pause_monitoring(self, repository: str) -> bool:
        if repository in self.monitored_repos:
            self.monitored_repos[repository].is_paused = True
            return True
        return False

    def resume_monitoring(self, repository: str) -> bool:
        if repository in self.monitored_repos:
            self.monitored_repos[repository].is_paused = False
            return True
        return False

    def get_pending_scheduled_jobs(self) -> list[dict[str, Any]]:
        """Return repositories due for periodic background scan."""
        pending = []
        now = datetime.now(timezone.utc)
        for repo_name, repo in self.monitored_repos.items():
            if repo.is_paused:
                continue
            if not repo.last_scan_at:
                pending.append({"repository": repo_name, "reason": "initial_scan"})
            else:
                elapsed_minutes = (now - repo.last_scan_at).total_seconds() / 60.0
                if elapsed_minutes >= repo.scan_frequency_minutes:
                    pending.append({"repository": repo_name, "reason": "periodic_schedule"})
        return pending
