"""Analyze Web Security Application Use Case Implementation."""

from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.web_security.engine import WebSecurityAnalysisEngine
from python_hunter.domain.web_security.models import (
    JWTSecurityConfig,
    RouteSecurityModel,
    SecurityBoundaryGraph,
    WebSecuritySummary,
)


class AnalyzeWebSecurityUseCase:
    """Orchestrates API, Web, Middleware, Auth, JWT, CSRF, CORS, and Microservice security analysis."""

    def __init__(self, ast_use_case: AnalyzeASTUseCase | None = None) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.engine = WebSecurityAnalysisEngine()

    def execute(
        self, target_path: str
    ) -> tuple[
        list[RouteSecurityModel],
        list[JWTSecurityConfig],
        SecurityBoundaryGraph,
        list[dict[str, Any]],
        WebSecuritySummary,
    ]:
        """Execute static web security analysis on target directory or file."""
        ast_summary = self.ast_use_case.execute(target_path)
        return self.engine.analyze(ast_summary.documents)
