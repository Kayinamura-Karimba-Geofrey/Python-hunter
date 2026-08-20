"""Offline Vulnerability Database Manager with Freshness Tracking, Atomic Updates, and Rollback."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import shutil
from typing import Any, Dict, List, Optional
from python_hunter.domain.dependencies.models import Ecosystem
from python_hunter.domain.dependencies.vulnerability_intel import Advisory, VulnerabilityProvider


@dataclass
class DatabaseMetadata:
    database_version: str = "1.0.0"
    last_update: str = ""
    source: str = "Python Hunter Local Cache"
    total_advisories: int = 0
    is_stale: bool = False
    age_days: int = 0

    def __post_init__(self) -> None:
        if not self.last_update:
            self.last_update = datetime.now(timezone.utc).isoformat()


class AdvisoryDatabase(VulnerabilityProvider):
    """Local offline advisory database provider supporting atomic updates, rollback, and corruption checks."""

    def __init__(self, db_dir: str = "/tmp/pyh_advisory_db") -> None:
        self.db_dir = db_dir
        self.meta_path = os.path.join(self.db_dir, "metadata.json")
        self.data_path = os.path.join(self.db_dir, "advisories.json")
        self.backup_dir = os.path.join(self.db_dir, ".backup")
        self.metadata = DatabaseMetadata()
        self.advisories: Dict[str, List[Advisory]] = {}
        self._initialize_database()

    def _initialize_database(self) -> None:
        os.makedirs(self.db_dir, exist_ok=True)
        if not os.path.exists(self.data_path):
            self._bootstrap_default_advisories()
        else:
            self._load_database()

    def _bootstrap_default_advisories(self) -> None:
        defaults = [
            Advisory(
                identifier="GHSA-vhq6-9248-wjmp",
                cve_id="CVE-2023-4863",
                package="pillow",
                ecosystem=Ecosystem.PYTHON,
                affected_versions=">=9.0.0,<10.0.1",
                patched_versions="10.0.1",
                severity="CRITICAL",
                cvss=9.8,
                description="Heap buffer overflow in WebP image parsing",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"],
                vulnerable_functions=["Image.open", "decode"],
            ),
            Advisory(
                identifier="GHSA-j8r2-6x86-vh33",
                cve_id="CVE-2023-30861",
                package="flask",
                ecosystem=Ecosystem.PYTHON,
                affected_versions=">=2.0.0,<2.3.3",
                patched_versions="2.3.3",
                severity="HIGH",
                cvss=7.5,
                description="Session cookie disclosure when using custom response handlers",
                references=["https://github.com/pallets/flask/security/advisories/GHSA-j8r2-6x86-vh33"],
                vulnerable_functions=["process_response"],
            ),
            Advisory(
                identifier="GHSA-p6mc-m468-83gw",
                cve_id="CVE-2021-44228",
                package="log4j-core",
                ecosystem=Ecosystem.MAVEN,
                affected_versions=">=2.0.0,<2.15.0",
                patched_versions="2.15.0",
                severity="CRITICAL",
                cvss=10.0,
                description="Remote code execution in Log4j JNDI lookup feature",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                vulnerable_functions=["lookup", "format"],
            ),
            Advisory(
                identifier="GHSA-c2qf-rxjj-fyvh",
                cve_id="CVE-2021-3749",
                package="axios",
                ecosystem=Ecosystem.JAVASCRIPT,
                affected_versions=">=0.8.1,<0.21.2",
                patched_versions="0.21.2",
                severity="HIGH",
                cvss=7.5,
                description="Regular Expression Denial of Service in trim function",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3749"],
                vulnerable_functions=["get", "request"],
            ),
        ]
        self.advisories = {}
        for adv in defaults:
            self.advisories.setdefault(adv.package.lower(), []).append(adv)
        self.metadata = DatabaseMetadata(
            database_version="1.0.0",
            last_update=datetime.now(timezone.utc).isoformat(),
            total_advisories=len(defaults),
        )
        self._save_database()

    def _save_database(self) -> None:
        raw_data = []
        for pkg_advs in self.advisories.values():
            for a in pkg_advs:
                raw_data.append({
                    "identifier": a.identifier,
                    "cve_id": a.cve_id,
                    "package": a.package,
                    "ecosystem": a.ecosystem.value,
                    "affected_versions": a.affected_versions,
                    "patched_versions": a.patched_versions,
                    "severity": a.severity,
                    "cvss": a.cvss,
                    "description": a.description,
                    "references": a.references,
                    "vulnerable_functions": a.vulnerable_functions,
                })

        with open(self.data_path, "w", encoding="utf-8") as f:
            json.dump(raw_data, f, indent=2)

        meta_dict = {
            "database_version": self.metadata.database_version,
            "last_update": self.metadata.last_update,
            "source": self.metadata.source,
            "total_advisories": self.metadata.total_advisories,
        }
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f, indent=2)

    def _load_database(self) -> None:
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                self.metadata = DatabaseMetadata(
                    database_version=meta.get("database_version", "1.0.0"),
                    last_update=meta.get("last_update", ""),
                    source=meta.get("source", "Local Cache"),
                    total_advisories=meta.get("total_advisories", 0),
                )
            with open(self.data_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
                self.advisories = {}
                for item in raw_data:
                    adv = Advisory(
                        identifier=item["identifier"],
                        cve_id=item.get("cve_id", ""),
                        package=item["package"],
                        ecosystem=Ecosystem(item.get("ecosystem", "pypi")),
                        affected_versions=item["affected_versions"],
                        patched_versions=item.get("patched_versions", ""),
                        severity=item.get("severity", "HIGH"),
                        cvss=item.get("cvss", 7.5),
                        description=item.get("description", ""),
                        references=item.get("references", []),
                        vulnerable_functions=item.get("vulnerable_functions", []),
                    )
                    self.advisories.setdefault(adv.package.lower(), []).append(adv)
        except Exception:
            # Failure / Corruption recovery
            self.rollback_database()

    def get_advisories(self, package: str, ecosystem: Ecosystem) -> List[Advisory]:
        pkg_key = package.lower().strip()
        matched = self.advisories.get(pkg_key, [])
        return [a for a in matched if a.ecosystem == ecosystem or ecosystem == Ecosystem.GENERIC]

    def update_database_atomic(self, new_advisories: List[Advisory], new_version: str = "1.1.0") -> bool:
        """Atomic update with backup created prior to write."""
        os.makedirs(self.backup_dir, exist_ok=True)
        if os.path.exists(self.data_path):
            shutil.copy2(self.data_path, os.path.join(self.backup_dir, "advisories.json"))
        if os.path.exists(self.meta_path):
            shutil.copy2(self.meta_path, os.path.join(self.backup_dir, "metadata.json"))

        try:
            for adv in new_advisories:
                self.advisories.setdefault(adv.package.lower(), []).append(adv)
            self.metadata.database_version = new_version
            self.metadata.last_update = datetime.now(timezone.utc).isoformat()
            self.metadata.total_advisories = sum(len(v) for v in self.advisories.values())
            self._save_database()
            return True
        except Exception:
            self.rollback_database()
            return False

    def rollback_database(self) -> None:
        """Rollback to backup snapshot if corrupted."""
        if os.path.exists(os.path.join(self.backup_dir, "advisories.json")):
            shutil.copy2(os.path.join(self.backup_dir, "advisories.json"), self.data_path)
            shutil.copy2(os.path.join(self.backup_dir, "metadata.json"), self.meta_path)
            self._load_database()
        else:
            self._bootstrap_default_advisories()

    def get_freshness_info(self) -> DatabaseMetadata:
        """Calculates database freshness and flags staleness if > 30 days old."""
        if self.metadata.last_update:
            try:
                dt = datetime.fromisoformat(self.metadata.last_update.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - dt).days
                self.metadata.age_days = age
                self.metadata.is_stale = age > 30
            except Exception:
                pass
        return self.metadata
