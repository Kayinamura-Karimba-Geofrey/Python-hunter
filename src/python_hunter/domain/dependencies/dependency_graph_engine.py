"""Dependency Graph Analytics Engine for depth, bloat, and Single Point of Failure (SPOF) detection."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.dependencies.models import Dependency, DependencyGraph, DependencyInventory


@dataclass
class GraphAnalytics:
    total_nodes: int = 0
    direct_count: int = 0
    transitive_count: int = 0
    max_depth: int = 0
    average_depth: float = 0.0
    bloat_factor: float = 1.0  # transitive / direct
    single_points_of_failure: List[Dict[str, Any]] = field(default_factory=list)


class DependencyGraphEngine:
    """Calculates dependency graph topology analytics, depth metrics, and SPOF concentrations."""

    @staticmethod
    def analyze_graph(graph: DependencyGraph) -> GraphAnalytics:
        total = len(graph.nodes)
        direct_count = len(graph.root_dependencies)
        transitive_count = max(0, total - direct_count)
        bloat_factor = (transitive_count / direct_count) if direct_count > 0 else 1.0

        depths: List[int] = []
        node_referrers: Dict[str, Set[str]] = {}

        def _dfs_depth(current: str, current_depth: int, visited: Set[str]) -> None:
            depths.append(current_depth)
            node = graph.nodes.get(current)
            if not node:
                return

            for child in node.dependencies:
                node_referrers.setdefault(child, set()).add(current)
                if child not in visited:
                    _dfs_depth(child, current_depth + 1, visited | {child})

        for root in graph.root_dependencies:
            _dfs_depth(root, 1, {root})

        max_depth = max(depths) if depths else 0
        avg_depth = (sum(depths) / len(depths)) if depths else 0.0

        # SPOF / Concentration Analysis: Packages required by multiple parent roots or packages
        spofs = []
        for child_name, parent_set in node_referrers.items():
            if len(parent_set) >= 2:
                spofs.append({
                    "package": child_name,
                    "dependents_count": len(parent_set),
                    "dependents": sorted(list(parent_set)),
                    "description": f"Critical dependency {child_name} is relied upon by {len(parent_set)} upstream packages.",
                })

        return GraphAnalytics(
            total_nodes=total,
            direct_count=direct_count,
            transitive_count=transitive_count,
            max_depth=max_depth,
            average_depth=round(avg_depth, 2),
            bloat_factor=round(bloat_factor, 2),
            single_points_of_failure=sorted(spofs, key=lambda x: x["dependents_count"], reverse=True),
        )
