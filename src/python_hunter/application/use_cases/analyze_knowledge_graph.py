"""Analyze Knowledge Graph Application Use Case Implementation."""

from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.graph.engine import SecurityKnowledgeGraphEngine
from python_hunter.domain.graph.models import AttackPath, SecurityGraph, WholeProjectRisk


class AnalyzeKnowledgeGraphUseCase:
    """Orchestrates Python Security Knowledge Graph construction, attack path resolution, and risk calculation."""

    def __init__(self, ast_use_case: AnalyzeASTUseCase | None = None) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.engine = SecurityKnowledgeGraphEngine()

    def execute(self, target_path: str) -> tuple[SecurityGraph, list[AttackPath], WholeProjectRisk]:
        """Execute static whole-project knowledge graph analysis on target directory or file."""
        ast_summary = self.ast_use_case.execute(target_path)
        return self.engine.analyze(ast_summary.documents)
