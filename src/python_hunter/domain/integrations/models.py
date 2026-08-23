"""Integration models, status, external references, and events."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IntegrationProviderType(str, Enum):
    """Supported enterprise integration provider types."""

    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    JIRA = "jira"
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"
    SSO = "sso"


class IntegrationStatus(str, Enum):
    """Health status of external integrations."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    DISCONNECTED = "DISCONNECTED"


@dataclass
class Integration:
    """Tenant-isolated Integration registration record."""

    integration_id: str
    organization_id: str
    provider: IntegrationProviderType
    name: str
    status: IntegrationStatus = IntegrationStatus.HEALTHY
    configuration: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_sync: datetime | None = None


@dataclass
class ExternalReference:
    """Mapping between Python Hunter resources and external tickets/checks."""

    reference_id: str
    organization_id: str
    internal_resource_type: str  # e.g. "finding", "incident"
    internal_resource_id: str
    provider: IntegrationProviderType
    external_id: str  # e.g. "SEC-101"
    external_url: str
    synchronization_state: str = "SYNCHRONIZED"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IntegrationEvent:
    """Normalized integration event payload."""

    event_id: str
    organization_id: str
    integration_id: str
    provider: IntegrationProviderType
    event_type: str
    payload: dict[str, Any]
    correlation_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
