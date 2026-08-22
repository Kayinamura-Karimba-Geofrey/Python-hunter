"""Domain models and data structures for Infrastructure-as-Code (IaC), Containers, Kubernetes, Cloud, and CI/CD."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.common.enums import Severity, Confidence


class InfrastructureResourceType(str, Enum):
    DOCKERFILE = "DOCKERFILE"
    DOCKER_COMPOSE = "DOCKER_COMPOSE"
    KUBERNETES_WORKLOAD = "KUBERNETES_WORKLOAD"  # Pod, Deployment, StatefulSet, DaemonSet
    KUBERNETES_SERVICE = "KUBERNETES_SERVICE"
    KUBERNETES_INGRESS = "KUBERNETES_INGRESS"
    KUBERNETES_RBAC = "KUBERNETES_RBAC"  # Role, ClusterRole, RoleBinding, ClusterRoleBinding
    KUBERNETES_SECRET = "KUBERNETES_SECRET"
    KUBERNETES_CONFIG = "KUBERNETES_CONFIG"
    HELM_CHART = "HELM_CHART"
    TERRAFORM_RESOURCE = "TERRAFORM_RESOURCE"
    TERRAFORM_MODULE = "TERRAFORM_MODULE"
    CLOUD_COMPUTE = "CLOUD_COMPUTE"
    CLOUD_STORAGE = "CLOUD_STORAGE"
    CLOUD_DATABASE = "CLOUD_DATABASE"
    CLOUD_NETWORK = "CLOUD_NETWORK"
    CLOUD_IAM = "CLOUD_IAM"
    GITHUB_ACTION_WORKFLOW = "GITHUB_ACTION_WORKFLOW"
    GENERIC_CICD = "GENERIC_CICD"


class InfrastructureEnvironment(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    UNKNOWN = "UNKNOWN"


@dataclass
class ContainerImage:
    """Represents a container image reference."""
    raw_reference: str
    registry: Optional[str] = None
    repository: Optional[str] = None
    tag: Optional[str] = None
    digest: Optional[str] = None
    is_pinned_by_digest: bool = False
    is_latest_or_unpinned: bool = False


@dataclass
class IAMPermission:
    """Represents an IAM policy statement/permission rule."""
    effect: str  # Allow / Deny
    actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    principals: List[str] = field(default_factory=list)
    has_wildcard_action: bool = False
    has_wildcard_resource: bool = False


@dataclass
class IAMPolicy:
    """Represents an IAM Policy or Kubernetes RBAC Role."""
    name: str
    principal_or_role: str
    permissions: List[IAMPermission] = field(default_factory=list)
    is_admin: bool = False


@dataclass
class InfrastructureResource:
    """Represents a parsed infrastructure resource node."""
    id: str
    name: str
    type: InfrastructureResourceType
    provider: str  # e.g., Docker, Kubernetes, AWS, Azure, GCP, GitHub
    file_path: str
    line: int = 1
    environment: InfrastructureEnvironment = InfrastructureEnvironment.UNKNOWN
    properties: Dict[str, Any] = field(default_factory=dict)
    container_images: List[ContainerImage] = field(default_factory=list)
    iam_policies: List[IAMPolicy] = field(default_factory=list)
    exposed_ports: List[int] = field(default_factory=list)
    is_publicly_exposed: bool = False
    is_privileged: bool = False
    runs_as_root: bool = False
    has_encryption_enabled: bool = True
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class InfrastructureGraphEdge:
    source_id: str
    target_id: str
    relation_type: str  # EXPOSES, MOUNTS, USES_IMAGE, USES_IAM, DEPENDS_ON


@dataclass
class InfrastructureGraph:
    """Configuration graph holding all resources and network/IAM dependency relationships."""
    resources: Dict[str, InfrastructureResource] = field(default_factory=dict)
    edges: List[InfrastructureGraphEdge] = field(default_factory=list)

    def add_resource(self, resource: InfrastructureResource) -> None:
        self.resources[resource.id] = resource

    def add_edge(self, source_id: str, target_id: str, relation_type: str) -> None:
        self.edges.append(InfrastructureGraphEdge(source_id, target_id, relation_type))


@dataclass
class InfrastructureIR:
    """Unified Intermediate Representation for Infrastructure, Containers, Cloud, and CI/CD."""
    scan_path: str
    resources: List[InfrastructureResource] = field(default_factory=list)
    graph: InfrastructureGraph = field(default_factory=InfrastructureGraph)
    dockerfiles: List[Dict[str, Any]] = field(default_factory=list)
    compose_files: List[Dict[str, Any]] = field(default_factory=list)
    kubernetes_manifests: List[Dict[str, Any]] = field(default_factory=list)
    helm_charts: List[Dict[str, Any]] = field(default_factory=list)
    terraform_files: List[Dict[str, Any]] = field(default_factory=list)
    cicd_workflows: List[Dict[str, Any]] = field(default_factory=list)
