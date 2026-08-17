"""Application Use Case for Vulnerability Intelligence Analysis."""

import logging
from typing import Any

from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.domain.dependencies.models import DependencyGraph, DependencyInventory
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import (
    PackageIdentity,
    Vulnerability,
    VulnerabilityMatch,
    VulnerabilityStatus,
)
from python_hunter.domain.vulnerabilities.providers.base import (
    ProviderStatus,
    VulnerabilityProvider,
)
from python_hunter.domain.vulnerabilities.version_matcher import VersionMatcher
from python_hunter.infrastructure.vulnerabilities.providers.cache import CachedVulnerabilityProvider
from python_hunter.infrastructure.vulnerabilities.providers.osv import OSVProvider
from python_hunter.rules.vulnerabilities import (
    PYHVuln001Confirmed,
    PYHVuln002Potential,
    PYHVuln003Unknown,
    PYHVuln004Withdrawn,
)

logger = logging.getLogger(__name__)


class AnalyzeVulnerabilitiesUseCase:
    """Orchestrates vulnerability intelligence querying, version matching, and finding generation."""

    def __init__(
        self,
        provider: VulnerabilityProvider | None = None,
        offline: bool = False,
    ) -> None:
        if provider is not None:
            self.provider = provider
        else:
            base_osv = OSVProvider()
            self.provider = CachedVulnerabilityProvider(base_osv, offline=offline)

        self.rules = [
            PYHVuln001Confirmed(),
            PYHVuln002Potential(),
            PYHVuln003Unknown(),
            PYHVuln004Withdrawn(),
        ]

    def execute(self, target_path: str) -> dict[str, Any]:
        """Execute vulnerability intelligence scan over target project path."""
        # 1. Discover dependencies via Step 6 Dependency Engine
        dep_use_case = AnalyzeDependenciesUseCase()
        dep_result = dep_use_case.execute(target_path)

        inventory: DependencyInventory = dep_result["inventory"]
        graph: DependencyGraph = inventory.graph

        # 2. Build package queries
        queries: list[tuple[PackageIdentity, str | None]] = []
        for dep in inventory.dependencies:
            pkg_identity = PackageIdentity(ecosystem="PyPI", name=dep.name)
            queries.append((pkg_identity, dep.version or None))

        # 3. Batch query vulnerability provider
        vuln_map = self.provider.batch_query(queries)

        # 4. Process matches and evaluate rules
        matches: list[VulnerabilityMatch] = []
        findings: list[Finding] = []
        seen_vuln_keys: set[str] = set()

        for dep in inventory.dependencies:
            norm_name = dep.normalized_name
            vulns = vuln_map.get(norm_name, [])

            # Compute paths in dependency graph
            paths = graph.get_paths_to(norm_name)

            if not vulns and not dep.version and not dep.version_constraint:
                # Unknown version case
                match = VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        id="UNKNOWN-VERSION",
                        summary="Unknown dependency version",
                        affected_package=norm_name,
                    ),
                    dependency=dep,
                    status=VulnerabilityStatus.UNKNOWN,
                    dependency_paths=paths,
                )
                matches.append(match)
                for rule in self.rules:
                    f = rule.evaluate_match(match)
                    if f:
                        findings.append(f)
                continue

            for vuln in vulns:
                # Deduplicate by (dep_name, vuln_id)
                dedup_key = f"{norm_name}:{vuln.id}"
                if dedup_key in seen_vuln_keys:
                    continue
                seen_vuln_keys.add(dedup_key)

                match = VersionMatcher.evaluate(vuln, dep, dependency_paths=paths)
                matches.append(match)

                for rule in self.rules:
                    finding = rule.evaluate_match(match)
                    if finding:
                        findings.append(finding)

        # 5. Summarize status counts
        status_counts = {
            "AFFECTED": sum(1 for m in matches if m.status == VulnerabilityStatus.AFFECTED),
            "POTENTIALLY_AFFECTED": sum(1 for m in matches if m.status == VulnerabilityStatus.POTENTIALLY_AFFECTED),
            "UNKNOWN": sum(1 for m in matches if m.status == VulnerabilityStatus.UNKNOWN),
            "NOT_AFFECTED": sum(1 for m in matches if m.status == VulnerabilityStatus.NOT_AFFECTED),
            "WITHDRAWN": sum(1 for m in matches if m.status == VulnerabilityStatus.WITHDRAWN),
        }

        return {
            "inventory": inventory,
            "graph": graph,
            "provider_name": self.provider.name,
            "provider_status": self.provider.status.value,
            "status_counts": status_counts,
            "matches": matches,
            "findings": findings,
        }
