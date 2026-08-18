"""Analyze Dynamic Application Use Case."""

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.dynamic.engine import DynamicBehaviorEngine
from python_hunter.domain.dynamic.models import (
    DynamicBehavior,
    DynamicBehaviorSummary,
)


class AnalyzeDynamicUseCase:
    """Orchestrates dynamic Python behavior analysis without executing code."""

    def __init__(self, ast_use_case: AnalyzeASTUseCase | None = None) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.engine = DynamicBehaviorEngine()

    def execute(self, target_path: str) -> tuple[list[DynamicBehavior], DynamicBehaviorSummary]:
        """Execute dynamic behavior analysis on target path."""
        ast_summary = self.ast_use_case.execute(target_path)
        return self.engine.analyze(ast_summary.documents)
