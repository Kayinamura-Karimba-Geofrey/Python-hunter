"""Security Knowledge Graph Engine Implementation."""

import logging
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.graph.analyzers import WholeProjectGraphBuilder
from python_hunter.domain.graph.models import AttackPath, SecurityGraph, WholeProjectRisk

logger = logging.getLogger(__name__)


class SecurityKnowledgeGraphEngine:
    """Orchestrates whole-project security knowledge graph assembly, attack path resolution, and risk calculation."""

    def __init__(self, mode: str = "balanced") -> None:
        self.mode = mode
        self.builder = WholeProjectGraphBuilder()

    def analyze(self, documents: list[ASTDocument]) -> tuple[SecurityGraph, list[AttackPath], WholeProjectRisk]:
        """Builds unified SecurityKnowledgeGraph and computes whole-project risk."""
        graph = SecurityGraph()
        self.builder.build_graph(documents, graph)

        # Resolve Attack Paths
        attack_paths: list[AttackPath] = []
        for edge in graph.edges:
            if edge.relationship.value == "FLOWS_TO":
                attack_paths.append(
                    AttackPath(
                        entry_point_id=edge.source_id,
                        target_asset_id=edge.target_id,
                        path_node_ids=[edge.source_id, edge.target_id],
                        risk_score=85.0,
                    )
                )

        # Calculate Whole-Project Security Risk
        total_risk = max([n.risk_score for n in graph.nodes.values()], default=0.0)
        project_risk = WholeProjectRisk(
            overall_score=total_risk,
            exposure_score=60.0 if len(attack_paths) > 0 else 10.0,
            vulnerability_score=total_risk,
            dependency_score=10.0,
            malware_score=10.0,
            control_coverage_score=50.0,
            critical_attack_paths_count=len(attack_paths),
        )

        return graph, attack_paths, project_risk
