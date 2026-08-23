"""Vulnerability Alias Graph & Identifier Deduplication Engine."""

from collections import defaultdict
from typing import Any

from python_hunter.domain.intelligence.models import VulnerabilityRecord, SourceTrustLevel


class VulnerabilityAliasGraph:
    """Maintains an undirected graph connecting CVE <-> GHSA <-> OSV <-> Vendor IDs

    and merges duplicate records into canonical VulnerabilityRecords.
    """

    def __init__(self) -> None:
        self._graph: dict[str, set[str]] = defaultdict(set)
        self._records: dict[str, VulnerabilityRecord] = {}

    def add_vulnerability(self, record: VulnerabilityRecord) -> None:
        """Add record and register all alias edges in graph."""
        all_ids = record.all_identifiers()
        self._records[record.vulnerability_id] = record

        for i in range(len(all_ids)):
            for j in range(i + 1, len(all_ids)):
                id1, id2 = all_ids[i], all_ids[j]
                self._graph[id1].add(id2)
                self._graph[id2].add(id1)

    def get_aliases(self, vuln_id: str) -> set[str]:
        """BFS / Connected Components traversal to find all linked aliases for an ID."""
        visited = set()
        queue = [vuln_id]

        while queue:
            curr = queue.pop(0)
            if curr not in visited:
                visited.add(curr)
                queue.extend(self._graph[curr] - visited)

        return visited

    def canonicalize_records(self, records: list[VulnerabilityRecord]) -> list[VulnerabilityRecord]:
        """Deduplicate records by clustering aliases and merging into canonical records."""
        for r in records:
            self.add_vulnerability(r)

        processed_ids = set()
        canonical_records = []

        for record in records:
            if record.vulnerability_id in processed_ids:
                continue

            all_linked_ids = self.get_aliases(record.vulnerability_id)
            processed_ids.update(all_linked_ids)

            # Gather all matching records in cluster
            cluster = [self._records[vid] for vid in all_linked_ids if vid in self._records]
            if not cluster:
                cluster = [record]

            # Merge cluster into single canonical record based on source trust
            merged = self._merge_cluster(cluster, all_linked_ids)
            canonical_records.append(merged)

        return canonical_records

    def _merge_cluster(
        self, cluster: list[VulnerabilityRecord], all_linked_ids: set[str]
    ) -> VulnerabilityRecord:
        """Sort cluster by source trust level (descending) and combine properties."""
        sorted_cluster = sorted(cluster, key=lambda x: int(x.source_trust), reverse=True)
        primary = sorted_cluster[0]

        # Prefer CVE prefix if available for primary ID display, else primary ID
        cve_ids = [vid for vid in all_linked_ids if vid.startswith("CVE-")]
        primary_id = cve_ids[0] if cve_ids else primary.vulnerability_id

        aliases = list(all_linked_ids - {primary_id})

        # Union fields across cluster
        cwes = set()
        cpes = set()
        refs = set()
        fixed_vers = set()
        affected_pkgs = []

        for item in sorted_cluster:
            cwes.update(item.cwe)
            cpes.update(item.cpe)
            refs.update(item.references)
            fixed_vers.update(item.fixed_versions)
            for pkg in item.affected_packages:
                if pkg not in affected_pkgs:
                    affected_pkgs.append(pkg)

        # Build merged record
        return VulnerabilityRecord(
            vulnerability_id=primary_id,
            aliases=aliases,
            title=primary.title or (sorted_cluster[1].title if len(sorted_cluster) > 1 else ""),
            description=primary.description,
            severity=primary.severity,
            cvss=primary.cvss or (sorted_cluster[1].cvss if len(sorted_cluster) > 1 else None),
            epss=primary.epss or (sorted_cluster[1].epss if len(sorted_cluster) > 1 else None),
            cwe=sorted(list(cwes)),
            cpe=sorted(list(cpes)),
            affected_packages=affected_pkgs,
            fixed_versions=sorted(list(fixed_vers)),
            references=sorted(list(refs)),
            published_at=primary.published_at,
            modified_at=primary.modified_at,
            lifecycle_state=primary.lifecycle_state,
            exploit_metadata=primary.exploit_metadata,
            source=primary.source,
            source_trust=primary.source_trust,
            fact_origin=primary.fact_origin,
        )
