"""Security Intelligence Engine - Core orchestrator for ingestion, normalization, correlation, and reassessment."""

from datetime import datetime, timezone
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.intelligence.alias_graph import VulnerabilityAliasGraph
from python_hunter.domain.intelligence.impact import ImpactNode, IntelligenceImpactGraph
from python_hunter.domain.intelligence.knowledge_base import SecurityKnowledgeBase
from python_hunter.domain.intelligence.models import (
    ConflictRecord,
    FactOrigin,
    IntelligenceFreshnessState,
    SourceTrustLevel,
    VulnerabilityHistoryEntry,
    VulnerabilityRecord,
)
from python_hunter.domain.intelligence.source import IntelligenceSourceRegistry
from python_hunter.domain.intelligence.version_range import VersionRangeEngine


class SecurityIntelligenceEngine:
    """Central Security Intelligence Engine combining Vulnerability Intelligence, Dependency Intelligence,

    Security Advisories, CWE, EPSS, CVSS, Attack Paths, and Verification Results.
    """

    def __init__(
        self,
        registry: IntelligenceSourceRegistry | None = None,
        knowledge_base: SecurityKnowledgeBase | None = None,
    ) -> None:
        self.registry = registry or IntelligenceSourceRegistry()
        self.knowledge_base = knowledge_base or SecurityKnowledgeBase()
        self.alias_graph = VulnerabilityAliasGraph()
        self.version_engine = VersionRangeEngine()
        self.impact_graph = IntelligenceImpactGraph()
        self._stored_records: dict[str, VulnerabilityRecord] = {}

    def ingest_intelligence(self, records: list[VulnerabilityRecord] | None = None) -> list[VulnerabilityRecord]:
        """Ingest intelligence from provided records and active sources in registry."""
        raw_records = []
        if records:
            raw_records.extend(records)
        raw_records.extend(self.registry.refresh_all())

        # Normalize and canonicalize records via alias graph and source trust level
        canonical_records = self.alias_graph.canonicalize_records(raw_records)

        for rec in canonical_records:
            existing = self._stored_records.get(rec.vulnerability_id)
            if existing:
                # Detect change & append history entry
                if existing.severity != rec.severity:
                    rec.history.append(
                        VulnerabilityHistoryEntry(
                            timestamp=datetime.now(timezone.utc),
                            field_changed="severity",
                            old_value=existing.severity.value,
                            new_value=rec.severity.value,
                            source=rec.source,
                        )
                    )
            self._stored_records[rec.vulnerability_id] = rec
            self.knowledge_base.register_vulnerability(rec)
            self._update_impact_nodes(rec)

        return list(self._stored_records.values())

    def _update_impact_nodes(self, rec: VulnerabilityRecord) -> None:
        """Register vulnerability and package nodes in impact graph."""
        v_node = ImpactNode(rec.vulnerability_id, "VULNERABILITY", rec.vulnerability_id)
        self.impact_graph.add_node(v_node)

        for pkg in rec.affected_packages:
            p_name = pkg.get("package", "unknown")
            p_id = f"PKG:{pkg.get('ecosystem','PyPI')}:{p_name}"
            p_node = ImpactNode(p_id, "PACKAGE", p_name)
            self.impact_graph.add_node(p_node)
            self.impact_graph.add_impact_edge(rec.vulnerability_id, p_id)

    def correlate_with_repository(
        self, repo_name: str, dependencies: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        """Correlate ingested vulnerabilities against a repository's dependencies."""
        repo_id = f"REPO:{repo_name}"
        self.impact_graph.add_node(ImpactNode(repo_id, "REPOSITORY", repo_name))

        matches = []
        for dep in dependencies:
            name = dep.get("name", "")
            ver = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "PyPI")

            pkg_id = f"PKG:{ecosystem}:{name}"
            self.impact_graph.add_node(ImpactNode(pkg_id, "PACKAGE", name))
            self.impact_graph.add_impact_edge(pkg_id, repo_id)

            for rec in self._stored_records.values():
                status = self.version_engine.evaluate_status(ver, rec.affected_packages, rec.fixed_versions)
                if status == "AFFECTED":
                    self.impact_graph.add_impact_edge(rec.vulnerability_id, pkg_id)
                    matches.append(
                        {
                            "vulnerability_id": rec.vulnerability_id,
                            "repository": repo_name,
                            "package": name,
                            "version": ver,
                            "severity": rec.severity.value,
                            "cvss": rec.cvss.base_score if rec.cvss else 5.0,
                            "epss": rec.epss.score if rec.epss else 0.0,
                            "fixed_versions": rec.fixed_versions,
                            "fact_origin": rec.fact_origin.value,
                            "explanation": f"Package {name} version {ver} falls within affected range for {rec.vulnerability_id}.",
                        }
                    )

        return matches

    def reassess_impact_on_change(
        self, changed_vuln_id: str, active_repos: dict[str, list[dict[str, str]]]
    ) -> list[dict[str, Any]]:
        """Automatically reassess only affected repositories when a vulnerability changes."""
        affected_repo_names = self.impact_graph.get_affected_repositories(changed_vuln_id)
        reassessed_matches = []

        for repo_name in affected_repo_names:
            if repo_name in active_repos:
                deps = active_repos[repo_name]
                m = self.correlate_with_repository(repo_name, deps)
                reassessed_matches.extend(m)

        return reassessed_matches
