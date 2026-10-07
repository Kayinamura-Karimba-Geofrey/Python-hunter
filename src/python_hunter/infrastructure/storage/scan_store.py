"""File-backed persistence for scan records, pull request analyses, and audit events."""

import json
import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def default_data_dir() -> Path:
    """Resolve the data directory from PYH_DATA_DIR, defaulting to ~/.python-hunter."""
    return Path(os.environ.get("PYH_DATA_DIR") or Path.home() / ".python-hunter")


class ScanResultStore:
    """Stores one JSON document per scan and an append-only audit log.

    Writes go through a temp file and an atomic rename, so a crash mid-write never leaves
    a truncated record behind. Records survive process restarts and are shared by every
    process pointed at the same data directory.
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else default_data_dir()
        self.scans_dir = self.root / "scans"
        self.prs_dir = self.root / "pull_requests"
        self.installations_dir = self.root / "installations"
        self.audit_file = self.root / "audit.jsonl"
        self._lock = threading.Lock()

    # Scan records

    def save_scan(self, record: dict[str, Any]) -> None:
        self._write(self.scans_dir, record["scan_id"], record)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        return self._read(self.scans_dir, scan_id)

    def list_scans(self, status: str | None = None) -> list[dict[str, Any]]:
        """Return scan records ordered oldest to newest."""
        records = self._read_all(self.scans_dir)
        if status:
            records = [r for r in records if r.get("status") == status]
        return sorted(records, key=lambda r: r.get("created_at", ""))

    def latest_scan(self, target: str | None = None) -> dict[str, Any] | None:
        completed = self.list_scans(status="COMPLETED")
        if target is not None:
            completed = [r for r in completed if r.get("target") == target]
        return completed[-1] if completed else None

    # Pull request analyses

    def save_pull_request(self, record: dict[str, Any]) -> None:
        self._write(self.prs_dir, record["pr_id"], record)

    def list_pull_requests(self) -> list[dict[str, Any]]:
        return sorted(self._read_all(self.prs_dir), key=lambda r: r.get("updated_at", ""), reverse=True)

    def get_pull_request(self, pr_id: str) -> dict[str, Any] | None:
        return self._read(self.prs_dir, pr_id)

    # GitHub App installations seen in webhook deliveries

    def save_installation(self, record: dict[str, Any]) -> None:
        self._write(self.installations_dir, record["installation_id"], record)

    def list_installations(self) -> list[dict[str, Any]]:
        return sorted(self._read_all(self.installations_dir), key=lambda r: r.get("installed_at", ""))

    def get_installation(self, installation_id: str) -> dict[str, Any] | None:
        return self._read(self.installations_dir, installation_id)

    # Audit log

    def append_audit(self, event: str, actor: str, resource: str, result: str = "SUCCESS") -> None:
        entry = {
            "event": event,
            "actor": actor,
            "timestamp": datetime.now(UTC).isoformat(),
            "resource": resource,
            "result": result,
        }
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            with self.audit_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def list_audit(self, limit: int = 500) -> list[dict[str, Any]]:
        if not self.audit_file.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self.audit_file.open(encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entry["id"] = f"aud-{idx}"
                entries.append(entry)
        return list(reversed(entries[-limit:]))

    # Internals

    @staticmethod
    def _path(directory: Path, record_id: str) -> Path:
        if not _SAFE_ID.match(record_id):
            raise ValueError(f"Invalid record id: {record_id!r}")
        return directory / f"{record_id}.json"

    def _write(self, directory: Path, record_id: str, record: dict[str, Any]) -> None:
        path = self._path(directory, record_id)
        with self._lock:
            directory.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(record, f, default=str)
                os.replace(tmp, path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise

    def _read(self, directory: Path, record_id: str) -> dict[str, Any] | None:
        try:
            path = self._path(directory, record_id)
        except ValueError:
            return None
        if not path.exists():
            return None
        try:
            with path.open(encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _read_all(directory: Path) -> list[dict[str, Any]]:
        if not directory.exists():
            return []
        records = []
        for path in directory.glob("*.json"):
            try:
                with path.open(encoding="utf-8") as f:
                    records.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                continue
        return records
