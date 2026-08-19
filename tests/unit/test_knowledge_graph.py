"""Unit tests for SecurityKnowledgeGraphEngine."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_knowledge_graph import AnalyzeKnowledgeGraphUseCase


class TestSecurityKnowledgeGraphEngine(unittest.TestCase):
    """Unit test suite for SecurityKnowledgeGraphEngine and whole-project graph resolvers."""

    def setUp(self) -> None:
        self.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "fixtures", "knowledge_graph")
        )
        self.ast_use_case = AnalyzeASTUseCase()
        self.use_case = AnalyzeKnowledgeGraphUseCase(ast_use_case=self.ast_use_case)

    def test_knowledge_graph_construction_and_attack_path(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "simple_project", "app.py")
        graph, attack_paths, project_risk = self.use_case.execute(fixture_path)

        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)
        self.assertGreater(len(attack_paths), 0)
        self.assertGreaterEqual(project_risk.overall_score, 0.0)

    def test_graph_query_public_vulnerabilities(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "simple_project", "app.py")
        graph, attack_paths, project_risk = self.use_case.execute(fixture_path)

        queries = graph.find_public_vulnerabilities()
        self.assertIsNotNone(queries)


if __name__ == "__main__":
    unittest.main()
