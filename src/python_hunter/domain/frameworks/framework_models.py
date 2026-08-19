"""Domain models for Framework-Aware Application Security Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.language.models import Language


class FrameworkCapability(str, Enum):
    """Capabilities supported by framework adapters."""

    ROUTE_DISCOVERY = "ROUTE_DISCOVERY"
    REQUEST_SOURCE_DISCOVERY = "REQUEST_SOURCE_DISCOVERY"
    AUTHENTICATION_DETECTION = "AUTHENTICATION_DETECTION"
    AUTHORIZATION_DETECTION = "AUTHORIZATION_DETECTION"
    ORM_ANALYSIS = "ORM_ANALYSIS"
    MIDDLEWARE_ANALYSIS = "MIDDLEWARE_ANALYSIS"
    CONFIGURATION_ANALYSIS = "CONFIGURATION_ANALYSIS"


class AuthStatus(str, Enum):
    """Authentication status of an application endpoint route."""

    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN = "UNKNOWN"


@dataclass
class Route:
    """Universal HTTP endpoint route representation."""

    http_method: str
    path: str
    handler_name: str
    file_path: str
    location: Location
    auth_status: AuthStatus = AuthStatus.UNKNOWN
    has_authorization_check: bool = False
    middleware: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)


@dataclass
class ApplicationModel:
    """Universal model representing an application instance, its framework, routes, and boundaries."""

    app_name: str
    framework_id: str
    framework_version: str
    language: Language
    routes: list[Route] = field(default_factory=list)
    middleware: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
