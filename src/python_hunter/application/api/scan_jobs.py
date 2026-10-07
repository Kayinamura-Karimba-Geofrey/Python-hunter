"""Background execution of API-submitted scans.

Scans run on a bounded thread pool so a request returns as soon as the job is queued.
Job state lives in the ScanResultStore, so it survives restarts. This assumes one API
process per data directory: at startup, any job left QUEUED or RUNNING is marked FAILED.
"""

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from python_hunter.application.services.security_app_service import SecurityApplicationService

logger = logging.getLogger(__name__)


class ScanJobManager:
    """Queues scans and records QUEUED → RUNNING → COMPLETED/FAILED transitions."""

    def __init__(self, service: SecurityApplicationService, max_workers: int = 2) -> None:
        self.service = service
        self.store = service.store
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="pyh-scan")
        self._fail_interrupted_jobs()

    def submit(self, target: str, profile: str, actor: str) -> dict[str, Any]:
        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "QUEUED",
            "created_at": _now(),
            "requested_by": actor,
        }
        self.store.save_scan(record)
        self._executor.submit(self._run, scan_id, target, profile, actor)
        return record

    def get(self, scan_id: str) -> dict[str, Any] | None:
        return self.store.get_scan(scan_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _run(self, scan_id: str, target: str, profile: str, actor: str) -> None:
        record = self.store.get_scan(scan_id) or {"scan_id": scan_id, "target": target, "created_at": _now()}
        record.update({"status": "RUNNING", "started_at": _now()})
        self.store.save_scan(record)
        try:
            # execute_scan overwrites the record with the COMPLETED result under the same id.
            self.service.execute_scan(target, profile, scan_id=scan_id, actor=actor)
        except Exception:
            logger.exception("Scan %s failed", scan_id)
            record.update({"status": "FAILED", "completed_at": _now(), "error": "Scan failed; see server logs."})
            self.store.save_scan(record)
            self.store.append_audit("SCAN_EXECUTED", actor, target, "FAILURE")

    def _fail_interrupted_jobs(self) -> None:
        """Jobs still QUEUED or RUNNING at startup were lost with the previous process."""
        for record in self.store.list_scans():
            if record.get("status") in ("QUEUED", "RUNNING"):
                record.update(
                    {"status": "FAILED", "completed_at": _now(), "error": "Interrupted by server restart."}
                )
                self.store.save_scan(record)


def _now() -> str:
    return datetime.now(UTC).isoformat()
