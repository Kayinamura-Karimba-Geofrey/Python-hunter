"""Role, Permission, Team, OrganizationMembership, and RBAC Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.governance.tenant import TenantContext


class SystemRole(str, Enum):
    """System-wide Role definitions."""

    ORGANIZATION_OWNER = "ORGANIZATION_OWNER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


# Central Role-Permission Matrix
ROLE_PERMISSIONS: dict[SystemRole, set[str]] = {
    SystemRole.ORGANIZATION_OWNER: {
        "admin.all",
        "repository.read",
        "repository.write",
        "finding.read",
        "finding.update",
        "scan.execute",
        "policy.read",
        "policy.write",
        "alert.read",
        "alert.update",
        "incident.read",
        "incident.update",
        "user.manage",
        "team.manage",
        "governance.approve",
        "audit.read",
    },
    SystemRole.SECURITY_ADMIN: {
        "repository.read",
        "repository.write",
        "finding.read",
        "finding.update",
        "scan.execute",
        "policy.read",
        "policy.write",
        "alert.read",
        "alert.update",
        "incident.read",
        "incident.update",
        "team.manage",
        "governance.approve",
        "audit.read",
    },
    SystemRole.SECURITY_ANALYST: {
        "repository.read",
        "finding.read",
        "finding.update",
        "scan.execute",
        "policy.read",
        "alert.read",
        "alert.update",
        "incident.read",
        "incident.update",
        "audit.read",
    },
    SystemRole.DEVELOPER: {
        "repository.read",
        "finding.read",
        "scan.execute",
        "policy.read",
        "alert.read",
    },
    SystemRole.AUDITOR: {
        "repository.read",
        "finding.read",
        "policy.read",
        "alert.read",
        "incident.read",
        "audit.read",
    },
    SystemRole.VIEWER: {
        "repository.read",
        "finding.read",
        "policy.read",
    },
}


@dataclass
class Team:
    """Team grouping within an Organization."""

    team_id: str
    organization_id: str
    name: str
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TeamMembership:
    """Team membership mapping."""

    user_id: str
    team_id: str
    role: SystemRole = SystemRole.DEVELOPER


@dataclass
class OrganizationMembership:
    """Organization membership mapping."""

    user_id: str
    organization_id: str
    role: SystemRole = SystemRole.VIEWER


class RBACEngine:
    """Centralized authorization decision engine enforcing tenant isolation and RBAC."""

    def build_tenant_context(
        self,
        user_id: str,
        organization_id: str,
        org_memberships: list[OrganizationMembership],
        team_memberships: list[TeamMembership],
    ) -> TenantContext:
        """Resolve permissions and build TenantContext for request/job."""
        user_roles: list[str] = []
        user_permissions: set[str] = set()

        for om in org_memberships:
            if om.user_id == user_id and om.organization_id == organization_id:
                user_roles.append(om.role.value)
                user_permissions.update(ROLE_PERMISSIONS.get(om.role, set()))

        team_ids = [tm.team_id for tm in team_memberships if tm.user_id == user_id]

        return TenantContext(
            user_id=user_id,
            organization_id=organization_id,
            team_ids=team_ids,
            roles=user_roles,
            permissions=user_permissions,
        )

    def authorize_request(
        self,
        context: TenantContext,
        target_organization_id: str,
        required_permission: str,
    ) -> bool:
        """Enforce strict tenant isolation and permission check."""
        # Tenant Isolation check
        if context.organization_id != target_organization_id:
            return False

        # Permission check
        return context.has_permission(required_permission)
