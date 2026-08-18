"""Domain Models for Python Framework Security Intelligence."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.ast.models import ASTLocation
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.findings.finding import Finding


class FrameworkType(str, Enum):
    """Supported Python Web and Infrastructure Frameworks."""

    FLASK = "FLASK"
    FASTAPI = "FASTAPI"
    DJANGO = "DJANGO"
    CELERY = "CELERY"
    SQLALCHEMY = "SQLALCHEMY"
    PYDANTIC = "PYDANTIC"
    JINJA2 = "JINJA2"
    REQUESTS_HTTPX = "REQUESTS_HTTPX"
    AUTH_LIBRARIES = "AUTH_LIBRARIES"
    UNKNOWN = "UNKNOWN"


@dataclass
class FrameworkEvidence:
    """Static evidence proving framework presence."""

    framework: FrameworkType
    confidence: Confidence
    evidence_type: str  # import, dependency, decorator, config, object
    source_element: str
    file_path: str | None = None
    line: int | None = None


@dataclass
class FrameworkRoute:
    """HTTP Route or Entry Point discovered in a framework application."""

    framework: FrameworkType
    http_method: str
    path: str
    handler_name: str
    handler_qualified_name: str
    file_path: str
    location: ASTLocation | None = None
    auth_required: bool = False
    csrf_protected: bool = True
    input_sources: list[str] = field(default_factory=list)
    sinks_reached: list[str] = field(default_factory=list)


@dataclass
class EndpointSecurityProfile:
    """Security posture profile for an individual endpoint."""

    route_path: str
    http_method: str
    handler_qualified_name: str
    framework: FrameworkType
    file_path: str
    auth_status: str  # REQUIRED, OPTIONAL, UNKNOWN, NONE
    csrf_status: str  # PROTECTED, EXEMPT, UNKNOWN
    inputs: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    taint_paths: int = 0
    risk_score: float = 0.0
    findings: list[Finding] = field(default_factory=list)


@dataclass
class APIInventory:
    """Aggregated inventory of all discovered API routes and endpoints."""

    total_endpoints: int = 0
    public_endpoints: int = 0
    authenticated_endpoints: int = 0
    high_risk_endpoints: int = 0
    endpoints: list[EndpointSecurityProfile] = field(default_factory=list)


@dataclass
class FrameworkProfile:
    """Summary of discovered framework intelligence across a project."""

    detected_frameworks: dict[FrameworkType, Confidence] = field(default_factory=dict)
    framework_versions: dict[FrameworkType, str] = field(default_factory=dict)
    evidences: list[FrameworkEvidence] = field(default_factory=list)
    routes: list[FrameworkRoute] = field(default_factory=list)
    api_inventory: APIInventory = field(default_factory=APIInventory)
