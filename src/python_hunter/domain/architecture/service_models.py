"""Domain models for Cross-Service API & Architecture Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.language.models import Language


class TrustBoundary(str, Enum):
    """Trust zone boundaries in a microservices system."""

    INTERNET = "INTERNET"
    PUBLIC_API = "PUBLIC_API"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    DATABASE = "DATABASE"
    EXTERNAL_API = "EXTERNAL_API"


@dataclass
class ApiClientCall:
    """Outbound API client call site from one service to another."""

    caller_service: str
    target_url: str
    http_method: str
    path: str
    file_path: str
    location: Location
    confidence: float = 0.8


@dataclass
class DatabaseAsset:
    """Data store entity connected to a service."""

    name: str
    db_type: str
    host: str = "localhost"


@dataclass
class ExternalService:
    """Outbound third-party service integration."""

    name: str
    target_url: str


@dataclass
class Service:
    """Microservice representation within a repository."""

    service_id: str
    name: str
    language: Language
    root_directory: str
    trust_boundary: TrustBoundary = TrustBoundary.INTERNAL_SERVICE
    endpoints: list[str] = field(default_factory=list)
    api_calls: list[ApiClientCall] = field(default_factory=list)
    databases: list[DatabaseAsset] = field(default_factory=list)
    external_services: list[ExternalService] = field(default_factory=list)


@dataclass
class InterServiceDataFlow:
    """Dataflow trace edge connecting an API client call in Service A to an endpoint in Service B."""

    source_service: str
    target_service: str
    target_endpoint: str
    http_method: str
    confidence: float = 0.85
