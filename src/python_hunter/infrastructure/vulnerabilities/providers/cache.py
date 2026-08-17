"""Cached and Offline Vulnerability Intelligence Provider Wrapper."""

from datetime import datetime, timedelta
import json
import logging
import os
from typing import Any

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


class CachedVulnerabilityProvider(VulnerabilityProvider):
    """Decorator provider that adds local disk & memory caching and offline mode support."""

    def __init__(
        self,
        inner_provider: VulnerabilityProvider,
        cache_dir: str = ".python_hunter_cache",
        ttl_hours: int = 24,
        offline: bool = False,
    ) -> None:
        self.inner_provider = inner_provider
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.offline = offline
        self._memory_cache: dict[str, list[Vulnerability]] = {}
        self._cache_file = os.path.join(cache_dir, "vulnerabilities_cache.json")
        self._load_cache()

    @property
    def name(self) -> str:
        suffix = " (Offline)" if self.offline else " (Cached)"
        return f"{self.inner_provider.name}{suffix}"

    @property
    def status(self) -> ProviderStatus:
        if self.offline:
            return ProviderStatus.OFFLINE
        return self.inner_provider.status

    def query(self, package: PackageIdentity, version: str | None = None) -> list[Vulnerability]:
        cache_key = f"{package.ecosystem}:{package.normalized_name}:{version or 'ANY'}"

        # 1. Memory / Disk Cache lookup
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]

        # 2. Offline mode: return empty if not cached
        if self.offline:
            logger.info(f"Offline mode: No cached vulnerability record for {cache_key}")
            return []

        # 3. Delegate to live inner provider
        vulns = self.inner_provider.query(package, version)
        self._memory_cache[cache_key] = vulns
        self._save_cache()
        return vulns

    def _load_cache(self) -> None:
        if not os.path.exists(self._cache_file):
            return
        try:
            with open(self._cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key, val in data.items():
                    self._memory_cache[key] = [self._dict_to_vuln(v) for v in val]
        except Exception as e:
            logger.warning(f"Failed to load vulnerability cache file: {e}")

    def _save_cache(self) -> None:
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            serializable: dict[str, Any] = {}
            for key, vulns in self._memory_cache.items():
                serializable[key] = [self._vuln_to_dict(v) for v in vulns]
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to write vulnerability cache file: {e}")

    def _vuln_to_dict(self, v: Vulnerability) -> dict[str, Any]:
        return {
            "id": v.id,
            "summary": v.summary,
            "description": v.description,
            "aliases": v.aliases,
            "affected_ecosystem": v.affected_ecosystem,
            "affected_package": v.affected_package,
            "affected_ranges": [
                {"range_type": r.range_type, "events": r.events, "database_specific": r.database_specific}
                for r in v.affected_ranges
            ],
            "fixed_versions": v.fixed_versions,
            "severity": v.severity.value,
            "cvss": {"version": v.cvss.version, "base_score": v.cvss.base_score, "vector_string": v.cvss.vector_string}
            if v.cvss
            else None,
            "references": v.references,
            "published_at": v.published_at.isoformat() if v.published_at else None,
            "modified_at": v.modified_at.isoformat() if v.modified_at else None,
            "withdrawn_at": v.withdrawn_at.isoformat() if v.withdrawn_at else None,
            "source": v.source,
            "metadata": v.metadata,
        }

    def _dict_to_vuln(self, d: dict[str, Any]) -> Vulnerability:
        from python_hunter.domain.common.enums import Severity

        cvss_d = d.get("cvss")
        cvss_obj = (
            CVSS(
                version=cvss_d["version"],
                base_score=cvss_d["base_score"],
                vector_string=cvss_d.get("vector_string", ""),
            )
            if cvss_d
            else None
        )

        return Vulnerability(
            id=d["id"],
            summary=d.get("summary", ""),
            description=d.get("description", ""),
            aliases=d.get("aliases", []),
            affected_ecosystem=d.get("affected_ecosystem", "PyPI"),
            affected_package=d.get("affected_package", ""),
            affected_ranges=[
                AffectedRange(
                    range_type=r.get("range_type", "ECOSYSTEM"),
                    events=r.get("events", []),
                    database_specific=r.get("database_specific", {}),
                )
                for r in d.get("affected_ranges", [])
            ],
            fixed_versions=d.get("fixed_versions", []),
            severity=Severity(d.get("severity", "MEDIUM")),
            cvss=cvss_obj,
            references=d.get("references", []),
            published_at=datetime.fromisoformat(d["published_at"]) if d.get("published_at") else None,
            modified_at=datetime.fromisoformat(d["modified_at"]) if d.get("modified_at") else None,
            withdrawn_at=datetime.fromisoformat(d["withdrawn_at"]) if d.get("withdrawn_at") else None,
            source=d.get("source", "Cache"),
            metadata=d.get("metadata", {}),
        )
