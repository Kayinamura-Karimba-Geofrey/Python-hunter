"""Security Intelligence Impact Graph linking Vulnerability -> Package -> Repository -> Application -> Attack Path."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImpactNode:
    """Node in Security Intelligence Impact Graph."""

    node_id: str
    node_type: str  # "VULNERABILITY", "PACKAGE", "REPOSITORY", "APPLICATION", "ATTACK_PATH", "ASSET"
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)


class IntelligenceImpactGraph:
    """Graph structure maintaining impact propagation across vulnerability relationships."""

    def __init__(self) -> None:
        self.nodes: dict[str, ImpactNode] = {}
        self.edges: dict[str, set[str]] = {}  # source_id -> set(target_ids)

    def add_node(self, node: ImpactNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.edges:
            self.edges[node.node_id] = set()

    def add_impact_edge(self, source_id: str, target_id: str) -> None:
        if source_id in self.nodes and target_id in self.nodes:
            self.edges[source_id].add(target_id)

    def get_affected_repositories(self, vuln_id: str) -> list[str]:
        """Find all repositories affected by a vulnerability ID."""
        affected_repos = set()
        visited = set()
        queue = [vuln_id]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)

            curr_node = self.nodes.get(curr)
            if curr_node and curr_node.node_type == "REPOSITORY":
                affected_repos.add(curr_node.name)

            for neighbor in self.edges.get(curr, set()):
                queue.append(neighbor)

        return sorted(list(affected_repos))

    def get_organization_impact(self) -> dict[str, Any]:
        """Summarize organization-wide vulnerability impact."""
        vulns = [n for n in self.nodes.values() if n.node_type == "VULNERABILITY"]
        repos = [n for n in self.nodes.values() if n.node_type == "REPOSITORY"]
        paths = [n for n in self.nodes.values() if n.node_type == "ATTACK_PATH"]

        return {
            "total_vulnerabilities": len(vulns),
            "affected_repositories_count": len(repos),
            "attack_paths_count": len(paths),
            "repositories": [r.name for r in repos],
        }
