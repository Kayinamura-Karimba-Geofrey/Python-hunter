"""Domain models for API, Web & Microservice Security Analysis Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.common.value_objects import Location


class AuthRequirement(str, Enum):
    """Route authentication requirement classification."""

    PUBLIC = "PUBLIC"
    AUTHENTICATED = "AUTHENTICATED"
    UNKNOWN = "UNKNOWN"


class AuthzMechanism(str, Enum):
    """Route authorization mechanism type."""

    NONE = "NONE"
    RBAC = "RBAC"
    ABAC = "ABAC"
    OWNERSHIP = "OWNERSHIP"
    SCOPE = "SCOPE"
    UNKNOWN = "UNKNOWN"


@dataclass
class RouteSecurityModel:
    """Represents the complete security posture of an API/web route."""

    route_path: str
    http_methods: list[str]
    handler_name: str
    file_path: str
    location: Location | None = None
    auth_requirement: AuthRequirement = AuthRequirement.UNKNOWN
    authz_mechanism: AuthzMechanism = AuthzMechanism.NONE
    roles_allowed: list[str] = field(default_factory=list)
    permissions_required: list[str] = field(default_factory=list)
    has_ownership_check: bool = False
    middleware_stack: list[str] = field(default_factory=list)
    request_models: list[str] = field(default_factory=list)
    response_models: list[str] = field(default_factory=list)
    is_csrf_protected: bool = True
    is_sensitive: bool = False
    confidence: Confidence = Confidence.HIGH
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class JWTSecurityConfig:
    """JWT configuration analysis details."""

    file_path: str
    location: Location | None = None
    verifies_signature: bool = True
    verifies_exp: bool = True
    verifies_aud: bool = False
    verifies_iss: bool = False
    algorithms: list[str] = field(default_factory=list)
    accepts_none: bool = False
    hardcoded_secret: bool = False


@dataclass
class SecurityBoundaryGraph:
    """Graph representing microservice trust boundaries and downstream endpoints."""

    nodes: set[str] = field(default_factory=set)  # clients, gateways, services, databases
    edges: list[dict[str, Any]] = field(default_factory=list)

    def add_service_call(self, caller: str, callee: str, protocol: str = "HTTP", authenticated: bool = False) -> None:
        self.nodes.add(caller)
        self.nodes.add(callee)
        self.edges.append({
            "caller": caller,
            "callee": callee,
            "protocol": protocol,
            "authenticated": authenticated,
        })


@dataclass
class BusinessWorkflowState:
    """Represents a business state machine transition or logic sequence."""

    workflow_name: str
    initial_state: str
    target_state: str
    is_valid_transition: bool = True
    requires_approval: bool = False
    file_path: str = ""
    location: Location | None = None


@dataclass
class WebSecuritySummary:
    """Statistical summary of Web Security analysis."""

    total_routes: int = 0
    public_routes: int = 0
    authenticated_routes: int = 0
    authorization_protected_routes: int = 0
    sensitive_routes: int = 0
    idor_candidates_count: int = 0
    ssrf_paths_count: int = 0
    jwt_config_issues: int = 0
    csrf_gaps_count: int = 0
    cors_issues_count: int = 0
