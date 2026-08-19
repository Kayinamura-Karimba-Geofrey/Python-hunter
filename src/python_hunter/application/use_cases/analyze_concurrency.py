"""Analyze Concurrency Application Use Case Implementation."""

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.concurrency.engine import ConcurrencyAnalysisEngine
from python_hunter.domain.concurrency.models import (
    ConcurrencyContext,
    ConcurrencySummary,
    LockOrderGraph,
    RaceCandidate,
    SharedResource,
    SynchronizationObject,
)


class AnalyzeConcurrencyUseCase:
    """Orchestrates static Python concurrency and asynchronous security analysis."""

    def __init__(self, ast_use_case: AnalyzeASTUseCase | None = None) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.engine = ConcurrencyAnalysisEngine()

    def execute(
        self, target_path: str
    ) -> tuple[
        list[ConcurrencyContext],
        list[SharedResource],
        list[SynchronizationObject],
        LockOrderGraph,
        list[RaceCandidate],
        ConcurrencySummary,
    ]:
        """Execute static concurrency analysis on target directory or file."""
        ast_summary = self.ast_use_case.execute(target_path)
        return self.engine.analyze(ast_summary.documents)
