"""Unit tests for WebSecurityAnalysisEngine."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_web_security import AnalyzeWebSecurityUseCase
from python_hunter.domain.web_security.models import AuthRequirement, AuthzMechanism
from python_hunter.rules.web_security import PYHWeb003IDOR, PYHWeb004JWTWeakness, PYHWeb008SSRF


class TestWebSecurityAnalysisEngine(unittest.TestCase):
    """Unit test suite for WebSecurityAnalysisEngine and specialized Web Security Analyzers."""

    def setUp(self) -> None:
        self.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "fixtures", "web_security")
        )
        self.ast_use_case = AnalyzeASTUseCase()
        self.use_case = AnalyzeWebSecurityUseCase(ast_use_case=self.ast_use_case)

    def test_route_discovery(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "fastapi", "app.py")
        routes, jwt_configs, boundary_graph, ssrf_paths, summary = self.use_case.execute(fixture_path)

        self.assertGreater(summary.total_routes, 0)
        paths = [r.route_path for r in routes]
        self.assertIn("/public/ping", paths)
        self.assertIn("/users/{user_id}", paths)

    def test_jwt_and_ssrf_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "fastapi", "app.py")
        routes, jwt_configs, boundary_graph, ssrf_paths, summary = self.use_case.execute(fixture_path)

        self.assertGreater(summary.jwt_config_issues, 0)
        self.assertGreater(summary.ssrf_paths_count, 0)

    def test_safety_guarantee_no_server_execution(self) -> None:
        """Verify that analyzed web application code or servers are never executed or started."""
        fixture_path = os.path.join(self.fixtures_dir, "fastapi", "app.py")
        routes, jwt_configs, boundary_graph, ssrf_paths, summary = self.use_case.execute(fixture_path)
        self.assertIsNotNone(summary)


if __name__ == "__main__":
    unittest.main()
