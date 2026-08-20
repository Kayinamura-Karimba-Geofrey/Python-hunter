"""Security Context Propagation, Trust Boundaries, and Security Invariant Enforcement."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set


class RoleLevel(str, Enum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    ADMINISTRATOR = "administrator"


class TrustBoundary(str, Enum):
    INTERNET = "internet"
    FRONTEND = "frontend"
    BACKEND = "backend"
    INTERNAL_SERVICE = "internal_service"
    DATABASE = "database"
    EXTERNAL_API = "external_api"


@dataclass
class SecurityContext:
    user_identity: Optional[str] = None
    role: RoleLevel = RoleLevel.ANONYMOUS
    tenant_id: Optional[str] = None
    is_authenticated: bool = False
    permissions: Set[str] = field(default_factory=set)
    current_boundary: TrustBoundary = TrustBoundary.INTERNET


@dataclass
class SecurityInvariant:
    name: str
    description: str
    required_role: RoleLevel = RoleLevel.AUTHENTICATED
    required_permission: Optional[str] = None
    requires_tenant_validation: bool = False


class InvariantViolation:
    def __init__(self, invariant_name: str, message: str, location_file: str, line_number: int) -> None:
        self.invariant_name = invariant_name
        self.message = message
        self.location_file = location_file
        self.line_number = line_number


class SecurityContextEngine:
    """Evaluates security invariant adherence and privilege transitions across trust boundaries."""

    def __init__(self) -> None:
        self.invariants: List[SecurityInvariant] = []
        self._bootstrap_invariants()

    def _bootstrap_invariants(self) -> None:
        self.invariants = [
            SecurityInvariant(
                name="sensitive_operation_requires_auth",
                description="Sensitive business operations must be invoked by authenticated users.",
                required_role=RoleLevel.AUTHENTICATED,
            ),
            SecurityInvariant(
                name="tenant_isolation_required",
                description="Multi-tenant operations must validate tenant_id matching authenticated context.",
                requires_tenant_validation=True,
            ),
            SecurityInvariant(
                name="admin_endpoint_requires_admin_role",
                description="Administrative endpoints require ADMINISTRATOR role level.",
                required_role=RoleLevel.ADMINISTRATOR,
            ),
        ]

    def validate_context(self, context: SecurityContext, invariant: SecurityInvariant, location_file: str, line_number: int) -> Optional[InvariantViolation]:
        if invariant.required_role == RoleLevel.ADMINISTRATOR and context.role != RoleLevel.ADMINISTRATOR:
            return InvariantViolation(
                invariant_name=invariant.name,
                message=f"Operation requires ADMINISTRATOR role, but caller context has {context.role.value}",
                location_file=location_file,
                line_number=line_number,
            )

        if invariant.required_role == RoleLevel.AUTHENTICATED and not context.is_authenticated:
            return InvariantViolation(
                invariant_name=invariant.name,
                message="Sensitive operation executed in unauthenticated ANONYMOUS context.",
                location_file=location_file,
                line_number=line_number,
            )

        if invariant.requires_tenant_validation and not context.tenant_id:
            return InvariantViolation(
                invariant_name=invariant.name,
                message="Multi-tenant data access missing tenant validation check.",
                location_file=location_file,
                line_number=line_number,
            )

        return None
