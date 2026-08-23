"""Security Intelligence Infrastructure - Local Database, Cache, and Source Providers."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.intelligence.models import (
    CVSSData,
    EPSSData,
    FactOrigin,
    IntelligenceFreshness,
    IntelligenceFreshnessState,
    SourceTrustLevel,
    VulnerabilityRecord,
)
from python_hunter.domain.intelligence.source import IntelligenceSource


class LocalIntelligenceDatabase:
    """Versioned SQLite database for persistent offline intelligence storage."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_info (
                    version INTEGER PRIMARY KEY,
                    updated_at TEXT
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerability_records (
                    id TEXT PRIMARY KEY,
                    raw_data TEXT,
                    source TEXT,
                    updated_at TEXT
                );
                """
            )
            # Set schema version
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_info (version, updated_at) VALUES (?, ?)",
                (self.SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
            )

    def save_records(self, records: list[VulnerabilityRecord]) -> None:
        with self._conn:
            for r in records:
                # Basic JSON serialization placeholder
                data = {
                    "vulnerability_id": r.vulnerability_id,
                    "title": r.title,
                    "description": r.description,
                    "severity": r.severity.value,
                    "fixed_versions": r.fixed_versions,
                    "source": r.source,
                }
                self._conn.execute(
                    "INSERT OR REPLACE INTO vulnerability_records (id, raw_data, source, updated_at) VALUES (?, ?, ?, ?)",
                    (r.vulnerability_id, json.dumps(data), r.source, datetime.now(timezone.utc).isoformat()),
                )

    def count(self) -> int:
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM vulnerability_records")
        return cur.fetchone()[0]


class OSVIntelligenceSource(IntelligenceSource):
    """Built-in OSV Intelligence Source with offline fallback fixtures."""

    def __init__(self, offline_mode: bool = True) -> None:
        self._offline_mode = offline_mode

    @property
    def name(self) -> str:
        return "OSV"

    @property
    def trust_level(self) -> SourceTrustLevel:
        return SourceTrustLevel.HIGH

    def fetch_records(self, ecosystem: str | None = None) -> list[VulnerabilityRecord]:
        # Return structured offline test records
        return [
            VulnerabilityRecord(
                vulnerability_id="GHSA-4v36-j8g8-hpj6",
                aliases=["CVE-2023-32681"],
                title="Requests HTTP header leakage in redirects",
                description="Unintended leak of Proxy-Authorization header during cross-origin redirect",
                severity=Severity.HIGH,
                cvss=CVSSData("3.1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", severity=Severity.HIGH),
                epss=EPSSData(0.15, 0.85),
                cwe=["CWE-200"],
                affected_packages=[{"ecosystem": "PyPI", "package": "requests", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
                fixed_versions=["2.31.0"],
                references=["https://github.com/psf/requests/security/advisories/GHSA-4v36-j8g8-hpj6"],
                source="OSV",
                source_trust=SourceTrustLevel.HIGH,
                fact_origin=FactOrigin.EXTERNAL_INTELLIGENCE,
            ),
            VulnerabilityRecord(
                vulnerability_id="CVE-2023-30861",
                aliases=["GHSA-j8r2-6x86-q33q"],
                title="Flask cookie disclosure via response headers",
                description="Flask session cookie exposed to unauthenticated attacker",
                severity=Severity.CRITICAL,
                cvss=CVSSData("3.1", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity=Severity.CRITICAL),
                epss=EPSSData(0.75, 0.95),
                cwe=["CWE-539"],
                affected_packages=[{"ecosystem": "PyPI", "package": "flask", "events": [{"introduced": "0"}, {"fixed": "2.3.2"}]}],
                fixed_versions=["2.3.2"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-30861"],
                source="NVD",
                source_trust=SourceTrustLevel.OFFICIAL,
                fact_origin=FactOrigin.FACT,
            ),
        ]

    def get_freshness(self) -> IntelligenceFreshness:
        return IntelligenceFreshness(
            source=self.name,
            version="1.0.0-bundled",
            fetched_at=datetime.now(timezone.utc),
            freshness=IntelligenceFreshnessState.FRESH if not self._offline_mode else IntelligenceFreshnessState.AGING,
        )
