"""OSV REST API Vulnerability Intelligence Provider."""

from datetime import datetime, timezone
import json
import logging
import urllib.error
import urllib.request
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.vulnerabilities.models import (
    CVSS,
    AffectedRange,
    PackageIdentity,
    Vulnerability,
)
from python_hunter.domain.vulnerabilities.providers.base import (
    ProviderStatus,
    VulnerabilityProvider,
)

logger = logging.getLogger(__name__)


class OSVProvider(VulnerabilityProvider):
    """Vulnerability provider accessing the Google Open Source Vulnerabilities (OSV) API."""

    BASE_URL = "https://api.osv.dev/v1/query"
    BATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, timeout_seconds: float = 5.0, user_agent: str = "PythonHunter/1.0") -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self._status = ProviderStatus.AVAILABLE

    @property
    def name(self) -> str:
        return "OSV"

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def query(self, package: PackageIdentity, version: str | None = None) -> list[Vulnerability]:
        """Query single package identity against OSV REST API."""
        payload: dict[str, Any] = {
            "package": {
                "name": package.normalized_name,
                "ecosystem": package.ecosystem or "PyPI",
            }
        }
        if version:
            payload["version"] = version

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.BASE_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status == 200:
                    resp_body = json.loads(resp.read().decode("utf-8"))
                    self._status = ProviderStatus.AVAILABLE
                    vulns = resp_body.get("vulns", [])
                    return [self._parse_osv_record(v, package.normalized_name) for v in vulns]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("OSV API Rate Limited (429)")
                self._status = ProviderStatus.RATE_LIMITED
            elif e.code >= 500:
                logger.warning(f"OSV API Server Error ({e.code})")
                self._status = ProviderStatus.PARTIAL
            else:
                logger.warning(f"OSV API HTTP Error ({e.code})")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning(f"OSV API Network Failure: {e}")
            self._status = ProviderStatus.UNAVAILABLE
        except Exception as e:
            logger.error(f"Error parsing OSV API response: {e}")
            self._status = ProviderStatus.ERROR

        return []

    def batch_query(
        self, queries: list[tuple[PackageIdentity, str | None]]
    ) -> dict[str, list[Vulnerability]]:
        """Batch query multiple packages against OSV API querybatch endpoint."""
        if not queries:
            return {}

        batch_queries = []
        for pkg, ver in queries:
            item: dict[str, Any] = {
                "package": {
                    "name": pkg.normalized_name,
                    "ecosystem": pkg.ecosystem or "PyPI",
                }
            }
            if ver:
                item["version"] = ver
            batch_queries.append(item)

        payload = {"queries": batch_queries}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.BATCH_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
            method="POST",
        )

        results: dict[str, list[Vulnerability]] = {}
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds * 2) as resp:
                if resp.status == 200:
                    resp_body = json.loads(resp.read().decode("utf-8"))
                    self._status = ProviderStatus.AVAILABLE
                    results_list = resp_body.get("results", [])
                    for (pkg, _), res_item in zip(queries, results_list):
                        vulns = res_item.get("vulns", [])
                        results[pkg.normalized_name] = [
                            self._parse_osv_record(v, pkg.normalized_name) for v in vulns
                        ]
                    return results
        except Exception as e:
            logger.warning(f"Batch query failed, falling back to sequential: {e}")

        # Fallback to sequential queries if batch query fails
        return super().batch_query(queries)

    def _parse_osv_record(self, raw: dict[str, Any], pkg_name: str) -> Vulnerability:
        """Parse raw OSV JSON vulnerability object into normalized Vulnerability entity."""
        vuln_id = raw.get("id", "UNKNOWN-OSV")
        summary = raw.get("summary") or (raw.get("details", "").split("\n")[0] if raw.get("details") else vuln_id)
        details = raw.get("details", "")
        aliases = raw.get("aliases", [])

        # Parse timestamps
        pub_dt = self._parse_iso_datetime(raw.get("published"))
        mod_dt = self._parse_iso_datetime(raw.get("modified"))
        withdrawn_dt = self._parse_iso_datetime(raw.get("withdrawn"))

        # Extract references
        refs = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

        # Extract affected ranges and fixed versions
        affected_ranges: list[AffectedRange] = []
        fixed_versions: list[str] = []

        for aff in raw.get("affected", []):
            for r in aff.get("ranges", []):
                r_type = r.get("type", "ECOSYSTEM")
                events = r.get("events", [])
                affected_ranges.append(AffectedRange(range_type=r_type, events=events))

                for ev in events:
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

            # Also collect versions explicitly listed as fixed
            for ver in aff.get("versions", []):
                pass  # Optional additional ver handling

        fixed_versions = list(dict.fromkeys(fixed_versions))  # Deduplicate keeping order

        # Severity & CVSS Normalization
        severity, cvss_obj = self._normalize_osv_severity(raw)

        return Vulnerability(
            id=vuln_id,
            summary=summary,
            description=details,
            aliases=aliases,
            affected_ecosystem="PyPI",
            affected_package=pkg_name,
            affected_ranges=affected_ranges,
            fixed_versions=fixed_versions,
            severity=severity,
            cvss=cvss_obj,
            references=refs,
            published_at=pub_dt,
            modified_at=mod_dt,
            withdrawn_at=withdrawn_dt,
            source="OSV",
            metadata=raw,
        )

    def _normalize_osv_severity(self, raw: dict[str, Any]) -> tuple[Severity, CVSS | None]:
        """Normalize OSV severity list and database_specific severity ratings into Severity enum & CVSS."""
        cvss_obj: CVSS | None = None
        severity = Severity.MEDIUM

        # Check OSV top-level severity field (CVSS v3 vector)
        severities = raw.get("severity", [])
        for s in severities:
            if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                vector = s.get("score", "")
                score = self._estimate_cvss_score(vector)
                sev_enum = self._score_to_severity(score)
                cvss_obj = CVSS(version="3.0", base_score=score, vector_string=vector, severity=sev_enum)
                return sev_enum, cvss_obj

        # Check database_specific / ecosystem severity strings
        db_spec = raw.get("database_specific", {})
        raw_sev = db_spec.get("severity", "").upper()
        if raw_sev in Severity.__members__:
            severity = Severity[raw_sev]

        return severity, cvss_obj

    @staticmethod
    def _estimate_cvss_score(vector: str) -> float:
        """Estimate base CVSS score from vector or return default score."""
        if "HIGH" in vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in vector:
            return 9.8
        if "CVSS:3" in vector:
            return 7.5
        return 5.0

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _parse_iso_datetime(dt_str: str | None) -> datetime | None:
        if not dt_str:
            return None
        try:
            # Handle standard ISO format ending with Z or offset
            dt_str = dt_str.replace("Z", "+00:00")
            return datetime.fromisoformat(dt_str)
        except Exception:
            return None
