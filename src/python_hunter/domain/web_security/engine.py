"""Web Security Analysis Engine Implementation."""

import logging
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.web_security.analyzers import BaseWebSecurityAnalyzer, JWTSessionAnalyzer, RouteAnalyzer
from python_hunter.domain.web_security.models import (
    AuthRequirement,
    AuthzMechanism,
    JWTSecurityConfig,
    RouteSecurityModel,
    SecurityBoundaryGraph,
    WebSecuritySummary,
)

logger = logging.getLogger(__name__)


class WebSecurityAnalysisEngine:
    """Orchestrates static API, Web, Middleware, Auth/Authz, JWT, CSRF, CORS, and SSRF security analysis."""

    def __init__(self, mode: str = "balanced") -> None:
        self.mode = mode
        self.analyzers: list[BaseWebSecurityAnalyzer] = [
            RouteAnalyzer(),
            JWTSessionAnalyzer(),
        ]

    def analyze(
        self, documents: list[ASTDocument]
    ) -> tuple[
        list[RouteSecurityModel],
        list[JWTSecurityConfig],
        SecurityBoundaryGraph,
        list[dict[str, Any]],
        WebSecuritySummary,
    ]:
        """Statically analyze AST documents for API, Web, and Microservice security architecture posture."""
        all_routes: list[RouteSecurityModel] = []
        all_jwt_configs: list[JWTSecurityConfig] = []
        boundary_graph = SecurityBoundaryGraph()
        all_ssrf: list[dict[str, Any]] = []
        all_cors: list[dict[str, Any]] = []

        for analyzer in self.analyzers:
            res = analyzer.analyze(documents)
            if "routes" in res:
                all_routes.extend(res["routes"])
            if "jwt_configs" in res:
                all_jwt_configs.extend(res["jwt_configs"])
            if "ssrf_paths" in res:
                all_ssrf.extend(res["ssrf_paths"])
            if "cors_issues" in res:
                all_cors.extend(res["cors_issues"])

        # Populate microservice boundary graph
        for ssrf in all_ssrf:
            boundary_graph.add_service_call("InternalApp", ssrf.get("client", "HTTPClient"))

        # Build statistical summary
        summary = WebSecuritySummary(
            total_routes=len(all_routes),
            public_routes=sum(1 for r in all_routes if r.auth_requirement == AuthRequirement.PUBLIC),
            authenticated_routes=sum(1 for r in all_routes if r.auth_requirement == AuthRequirement.AUTHENTICATED),
            authorization_protected_routes=sum(1 for r in all_routes if r.authz_mechanism != AuthzMechanism.NONE),
            sensitive_routes=sum(1 for r in all_routes if r.is_sensitive),
            idor_candidates_count=sum(1 for r in all_routes if r.auth_requirement == AuthRequirement.AUTHENTICATED and not r.has_ownership_check),
            ssrf_paths_count=len(all_ssrf),
            jwt_config_issues=sum(1 for j in all_jwt_configs if not j.verifies_signature),
            csrf_gaps_count=sum(1 for r in all_routes if not r.is_csrf_protected and r.auth_requirement == AuthRequirement.PUBLIC),
            cors_issues_count=len(all_cors),
        )

        return all_routes, all_jwt_configs, boundary_graph, all_ssrf, summary
