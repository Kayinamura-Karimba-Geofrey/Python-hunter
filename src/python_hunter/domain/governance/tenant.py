"""Tenant, Organization, Environment, and Project models for multi-tenancy."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class OrganizationStatus(str, Enum):
    """Organization tenant lifecycle status."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    ARCHIVED = "ARCHIVED"


class Environment(str, Enum):
    """Environment classification influencing risk calculations."""

    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class AssetCriticality(str, Enum):
    """Business criticality rating."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Organization:
    """Multi-tenant Organization boundary."""

    organization_id: str
    name: str
    slug: str
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Project:
    """Project grouping repositories under a Team and Organization."""

    project_id: str
    organization_id: str
    name: str
    owner_team_id: str
    environment: Environment = Environment.DEVELOPMENT
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TenantContext:
    """Encapsulates authenticated tenant execution context for requests and background jobs."""

    user_id: str
    organization_id: str
    team_ids: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    permissions: set[str] = field(default_factory=set)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions or "admin.all" in self.permissions
