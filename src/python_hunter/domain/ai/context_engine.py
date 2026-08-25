"""Security Context Engine for business impact, environment awareness, and asset criticality."""

from typing import Dict, Optional
from python_hunter.domain.ai.models import (
    AssetCriticality, EnvironmentType, InternetExposure, SecurityContext
)


class SecurityContextEngine:
    """Collects and resolves organizational security context for target repositories and assets."""

    def __init__(self) -> None:
        # Pre-configured registry of project contexts
        self._contexts: Dict[str, SecurityContext] = {}

    def register_context(self, repo_name: str, context: SecurityContext) -> None:
        self._contexts[repo_name] = context

    def get_context(
        self,
        repo_name: str,
        environment: Optional[EnvironmentType] = None,
        exposure: Optional[InternetExposure] = None
    ) -> SecurityContext:
        ctx = self._contexts.get(repo_name)
        if not ctx:
            ctx = SecurityContext(
                repository=repo_name,
                asset_criticality=AssetCriticality.MEDIUM,
                internet_exposure=exposure or InternetExposure.UNKNOWN,
                environment=environment or EnvironmentType.DEVELOPMENT
            )
        else:
            if environment:
                ctx.environment = environment
                ctx.is_production = (environment == EnvironmentType.PRODUCTION)
            if exposure:
                ctx.internet_exposure = exposure

        return ctx
