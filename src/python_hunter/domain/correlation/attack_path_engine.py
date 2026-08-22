"""Attack Path Engine, Asset Inventory, What-If Analyzer, and Remediation Impact Calculator."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from python_hunter.domain.common.enums import Confidence, Severity, AssetCriticality, DataSensitivity, TrustBoundary, PrivilegeLevel
from python_hunter.domain.graph.models import SecurityGraph, NodeType, EdgeType, SecurityNode, SecurityEdge, AttackPath


@dataclass
class AssetInventory:
    """Centralized asset inventory tracking applications, services, APIs, databases, containers, and cloud resources."""

    repositories: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    apis: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    databases: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    containers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    cloud_resources: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class RemediationImpact:
    """Calculated impact of fixing a finding or set of findings on the overall attack path landscape."""

    finding_id: str
    broken_attack_path_ids: List[str] = field(default_factory=list)
    remaining_attack_path_ids: List[str] = field(default_factory=list)
    risk_reduction_score: float = 0.0
    affected_assets: List[str] = field(default_factory=list)


class AttackPathEngine:
    """Discovers, validates, ranks, and analyzes evidence-backed attack paths across the entire security knowledge graph."""

    def __init__(self, max_depth: int = 10, max_paths: int = 50) -> None:
        self.max_depth = max_depth
        self.max_paths = max_paths

    def find_all_attack_paths(self, graph: SecurityGraph) -> List[AttackPath]:
        """Traces all evidence-backed paths from Entry Points -> Target Assets."""
        attack_paths: List[AttackPath] = []
        entry_nodes = [n for n in graph.nodes.values() if n.is_entry_point or n.type in (NodeType.API_ENDPOINT, NodeType.TAINT_SOURCE, NodeType.CICD_WORKFLOW, NodeType.NETWORK)]
        target_nodes = [n for n in graph.nodes.values() if n.is_sensitive_asset or n.type in (NodeType.DATABASE, NodeType.STORAGE, NodeType.CLOUD_RESOURCE, NodeType.SECRET)]

        if not entry_nodes:
            # Fallback to Internet or any public node
            entry_nodes = [n for n in graph.nodes.values() if "internet" in n.name.lower() or "public" in n.name.lower()]
        if not target_nodes:
            target_nodes = [n for n in graph.nodes.values() if n.risk_score >= 70.0]

        visited_paths: Set[Tuple[str, ...]] = set()

        for entry in entry_nodes:
            for target in target_nodes:
                if entry.id == target.id:
                    continue
                paths = self._dfs_find_paths(graph, entry.id, target.id, current_path=[entry.id], depth=0)
                for p_ids in paths:
                    t_tuple = tuple(p_ids)
                    if t_tuple in visited_paths:
                        continue
                    visited_paths.add(t_tuple)

                    ap = self._build_attack_path(graph, entry, target, p_ids)
                    attack_paths.append(ap)
                    if len(attack_paths) >= self.max_paths:
                        break

        # Sort attack paths by risk score descending
        attack_paths.sort(key=lambda x: x.risk_score, reverse=True)
        return attack_paths

    def _dfs_find_paths(
        self, graph: SecurityGraph, current_id: str, target_id: str, current_path: List[str], depth: int
    ) -> List[List[str]]:
        if depth >= self.max_depth:
            return []
        if current_id == target_id:
            return [current_path]

        results = []
        for edge in graph.get_neighbors(current_id):
            nxt_id = edge.target_id
            if nxt_id not in current_path:
                res = self._dfs_find_paths(graph, nxt_id, target_id, current_path + [nxt_id], depth + 1)
                results.extend(res)
                if len(results) >= 10:
                    break
        return results

    def _build_attack_path(
        self, graph: SecurityGraph, entry_node: SecurityNode, target_node: SecurityNode, path_ids: List[str]
    ) -> AttackPath:
        path_id = f"ap-{hash(tuple(path_ids)) & 0xffffff:06x}"
        node_names = [graph.nodes[nid].name if nid in graph.nodes else nid for nid in path_ids]
        title = f"{entry_node.name} → {' → '.join(node_names[1:-1])} → {target_node.name}" if len(node_names) > 2 else f"{entry_node.name} → {target_node.name}"

        # Collect evidence & transitions
        evidences = []
        trust_trans = [TrustBoundary.INTERNET.value, TrustBoundary.APPLICATION.value]
        priv_trans = [PrivilegeLevel.UNAUTHENTICATED.value]

        for i in range(len(path_ids) - 1):
            src, dst = path_ids[i], path_ids[i + 1]
            edges = [e for e in graph.get_neighbors(src) if e.target_id == dst]
            if edges:
                e = edges[0]
                evidences.append({
                    "from": graph.nodes[src].name if src in graph.nodes else src,
                    "to": graph.nodes[dst].name if dst in graph.nodes else dst,
                    "relationship": e.relationship.value,
                    "evidence": e.evidence,
                    "confidence": e.confidence.value,
                })

        # Calculate risk score
        max_node_risk = max([graph.nodes[nid].risk_score for nid in path_ids if nid in graph.nodes], default=50.0)
        path_risk = min(100.0, max_node_risk + (len(path_ids) * 3.0))

        # Severity
        if path_risk >= 85.0:
            sev = Severity.CRITICAL
        elif path_risk >= 70.0:
            sev = Severity.HIGH
        elif path_risk >= 50.0:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW

        explanation = f"An attacker starting at {entry_node.name} can traverse security controls through {len(path_ids)-2} intermediate components to compromise sensitive asset {target_node.name}."
        remediation = f"Fix the entry point vulnerability at {entry_node.name} or restrict permissions accessing {target_node.name}."

        return AttackPath(
            id=path_id,
            title=title,
            entry_point_id=entry_node.id,
            target_asset_id=target_node.id,
            path_node_ids=path_ids,
            risk_score=round(path_risk, 1),
            confidence=Confidence.HIGH,
            severity=sev,
            validity=True,
            evidence_chain=evidences,
            trust_transitions=trust_trans,
            privilege_transitions=priv_trans,
            business_impact={"confidentiality": "HIGH", "integrity": "HIGH", "regulatory": "NON_COMPLIANT"},
            explanation=explanation,
            remediation_guidance=remediation,
            remediation_impact_score=round(len(path_ids) * 1.5, 1),
        )


class WhatIfAnalyzer:
    """Performs hypothetical what-if remediation simulation to measure residual risk without altering state."""

    @staticmethod
    def simulate_remediation(
        original_graph: SecurityGraph,
        engine: AttackPathEngine,
        removed_node_ids: List[str],
    ) -> Dict[str, Any]:
        """Simulates removing nodes/findings and recalculates residual attack paths and risk delta."""
        # Create lightweight copy of graph
        sim_graph = SecurityGraph()
        for nid, node in original_graph.nodes.items():
            if nid not in removed_node_ids:
                sim_graph.add_node(node)

        for edge in original_graph.edges:
            if edge.source_id not in removed_node_ids and edge.target_id not in removed_node_ids:
                sim_graph.add_edge(edge)

        before_paths = engine.find_all_attack_paths(original_graph)
        after_paths = engine.find_all_attack_paths(sim_graph)

        before_risk = max([p.risk_score for p in before_paths], default=0.0)
        after_risk = max([p.risk_score for p in after_paths], default=0.0)

        broken_paths = [p for p in before_paths if any(nid in removed_node_ids for nid in p.path_node_ids)]

        return {
            "remediated_nodes": removed_node_ids,
            "before_attack_paths_count": len(before_paths),
            "after_attack_paths_count": len(after_paths),
            "broken_attack_paths_count": len(broken_paths),
            "broken_attack_paths": [p.title for p in broken_paths],
            "before_max_risk_score": before_risk,
            "after_max_risk_score": after_risk,
            "risk_reduction": round(max(0.0, before_risk - after_risk), 1),
            "residual_attack_paths": [
                {
                    "id": p.id,
                    "title": p.title,
                    "risk_score": p.risk_score,
                    "severity": p.severity.value,
                }
                for p in after_paths
            ],
        }
