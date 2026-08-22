"""Domain models for Python Security Knowledge Graph Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Confidence, Severity, TrustBoundary, PrivilegeLevel, AssetCriticality, DataSensitivity
from python_hunter.domain.common.value_objects import Location


class NodeType(str, Enum):
    """Types of entities in the Security Knowledge Graph."""

    REPOSITORY = "REPOSITORY"
    APPLICATION = "APPLICATION"
    SERVICE = "SERVICE"
    MODULE = "MODULE"
    FUNCTION = "FUNCTION"
    API_ENDPOINT = "API_ENDPOINT"
    DEPENDENCY = "DEPENDENCY"
    VULNERABILITY = "VULNERABILITY"
    SECRET = "SECRET"
    CONTAINER = "CONTAINER"
    IMAGE = "IMAGE"
    KUBERNETES_RESOURCE = "KUBERNETES_RESOURCE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    IDENTITY = "IDENTITY"
    PERMISSION = "PERMISSION"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    STORAGE = "STORAGE"
    CICD_WORKFLOW = "CICD_WORKFLOW"
    GIT_COMMIT = "GIT_COMMIT"
    PULL_REQUEST = "PULL_REQUEST"
    ENVIRONMENT = "ENVIRONMENT"
    FINDING = "FINDING"
    # Backwards compatibility aliases
    PROJECT = "REPOSITORY"
    TAINT_SOURCE = "API_ENDPOINT"
    TAINT_SINK = "VULNERABILITY"
    SECURITY_CONTROL = "PERMISSION"
    EXPLOIT_PATH = "FINDING"
    MALWARE_BEHAVIOR = "FINDING"
    CRITICAL_ASSET = "DATABASE"


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
    AUTHENTICATES = "AUTHENTICATES"
    GRANTS = "GRANTS"
    DEPLOYS = "DEPLOYS"
    ASSUMES_ROLE = "ASSUMES_ROLE"
    CONNECTS_TO = "CONNECTS_TO"
    USES_SECRET = "USES_SECRET"
    TARGETS_WORKLOAD = "TARGETS_WORKLOAD"
    RUNS_IN = "RUNS_IN"


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
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    is_entry_point: bool = False
    is_sensitive_asset: bool = False


@dataclass
class SecurityEdge:
    """Represents an evidence-backed directed edge between nodes in the Security Knowledge Graph."""

    source_id: str
    target_id: str
    relationship: EdgeType
    evidence: str = ""
    source: str = "static_analysis"
    analysis_type: str = "ast_callgraph"
    confidence: Confidence = Confidence.HIGH


@dataclass
class AttackPath:
    """Reconstructed attack path through the Security Knowledge Graph."""

    id: str = ""
    title: str = ""
    entry_point_id: str = ""
    target_asset_id: str = ""
    path_node_ids: list[str] = field(default_factory=list)
    bypassed_controls: list[str] = field(default_factory=list)
    risk_score: float = 90.0
    confidence: Confidence = Confidence.HIGH
    severity: Severity = Severity.CRITICAL
    validity: bool = True
    primary_cause_finding_id: str | None = None
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    trust_transitions: list[str] = field(default_factory=list)
    privilege_transitions: list[str] = field(default_factory=list)
    business_impact: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    remediation_guidance: str = ""
    remediation_impact_score: float = 1.0


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
                if src_node and tgt_node and (src_node.is_entry_point or src_node.type in (NodeType.API_ENDPOINT, NodeType.TAINT_SOURCE)):
                    results.append({
                        "source": src_node.name,
                        "target": tgt_node.name,
                        "relationship": edge.relationship.value,
                        "risk_score": tgt_node.risk_score,
                    })
        return results
