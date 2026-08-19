"""Domain models for Python Security Knowledge Graph Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.common.value_objects import Location


class NodeType(str, Enum):
    """Types of entities in the Security Knowledge Graph."""

    PROJECT = "PROJECT"
    MODULE = "MODULE"
    FUNCTION = "FUNCTION"
    API_ENDPOINT = "API_ENDPOINT"
    DEPENDENCY = "DEPENDENCY"
    VULNERABILITY = "VULNERABILITY"
    SECRET = "SECRET"
    TAINT_SOURCE = "TAINT_SOURCE"
    TAINT_SINK = "TAINT_SINK"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    EXPLOIT_PATH = "EXPLOIT_PATH"
    MALWARE_BEHAVIOR = "MALWARE_BEHAVIOR"
    GIT_COMMIT = "GIT_COMMIT"
    CRITICAL_ASSET = "CRITICAL_ASSET"


class EdgeType(str, Enum):
    """Relationships between entities in the Security Knowledge Graph."""

    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    AFFECTED_BY = "AFFECTED_BY"
    FLOWS_TO = "FLOWS_TO"
    PROTECTS = "PROTECTS"
    BYPASSES = "BYPASSES"
    REACHES = "REACHES"
    INTRODUCED_BY = "INTRODUCED_BY"
    EXPOSES = "EXPOSES"


@dataclass
class SecurityNode:
    """Represents a node in the Security Knowledge Graph."""

    id: str
    type: NodeType
    name: str
    file_path: str = ""
    location: Location | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    confidence: Confidence = Confidence.HIGH


@dataclass
class SecurityEdge:
    """Represents a directed edge between nodes in the Security Knowledge Graph."""

    source_id: str
    target_id: str
    relationship: EdgeType
    evidence: str = ""
    confidence: Confidence = Confidence.HIGH


@dataclass
class AttackPath:
    """Reconstructed attack path through the Security Knowledge Graph."""

    entry_point_id: str
    target_asset_id: str
    path_node_ids: list[str] = field(default_factory=list)
    bypassed_controls: list[str] = field(default_factory=list)
    risk_score: float = 90.0
    confidence: Confidence = Confidence.HIGH


@dataclass
class SecurityStory:
    """Correlated security narrative uniting findings across code, dependencies, and APIs."""

    title: str
    description: str
    attack_path: AttackPath
    impact: str
    remediation: str


@dataclass
class WholeProjectRisk:
    """Aggregated project-level security risk score and breakdown."""

    overall_score: float
    exposure_score: float
    vulnerability_score: float
    dependency_score: float
    malware_score: float
    control_coverage_score: float
    critical_attack_paths_count: int


class SecurityGraph:
    """In-memory directed Graph container for security entities and relationships."""

    def __init__(self) -> None:
        self.nodes: dict[str, SecurityNode] = {}
        self.edges: list[SecurityEdge] = []
        self._adj_list: dict[str, list[SecurityEdge]] = {}

    def add_node(self, node: SecurityNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adj_list:
            self._adj_list[node.id] = []

    def add_edge(self, edge: SecurityEdge) -> None:
        self.edges.append(edge)
        if edge.source_id not in self._adj_list:
            self._adj_list[edge.source_id] = []
        self._adj_list[edge.source_id].append(edge)

    def get_neighbors(self, node_id: str) -> list[SecurityEdge]:
        return self._adj_list.get(node_id, [])

    def find_public_vulnerabilities(self) -> list[dict[str, Any]]:
        """Queries the graph for vulnerabilities reachable from public entry points."""
        results = []
        for edge in self.edges:
            if edge.relationship in (EdgeType.FLOWS_TO, EdgeType.REACHES):
                src_node = self.nodes.get(edge.source_id)
                tgt_node = self.nodes.get(edge.target_id)
                if src_node and tgt_node and src_node.type in (NodeType.API_ENDPOINT, NodeType.TAINT_SOURCE):
                    results.append({
                        "source": src_node.name,
                        "target": tgt_node.name,
                        "relationship": edge.relationship.value,
                        "risk_score": tgt_node.risk_score,
                    })
        return results
