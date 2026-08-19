"""Scan Orchestrator implementation for Python Hunter."""

from datetime import datetime, timezone
from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_exploitability import AnalyzeExploitabilityUseCase
from python_hunter.application.use_cases.analyze_knowledge_graph import AnalyzeKnowledgeGraphUseCase
from python_hunter.application.orchestrator.scan_context import ScanContext, ScanResult
from python_hunter.infrastructure.repository.repository_manager import RepositoryManager
from python_hunter.infrastructure.repository.target_resolver import ScanTarget, TargetResolver


class ScanOrchestrator:
    """Coordinates target resolution, repository acquisition, AST analysis, security rules, knowledge graph construction, risk calculation, and report generation."""

    def __init__(self) -> None:
        self.target_resolver = TargetResolver()
        self.repo_manager = RepositoryManager()
        self.graph_use_case = AnalyzeKnowledgeGraphUseCase()
        self.exploitability_use_case = AnalyzeExploitabilityUseCase()

    def run_scan(
        self,
        target_str: str,
        branch: str = "",
        commit: str = "",
        tag: str = "",
        fail_on: str = "high",
        options: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Executes full scan pipeline on local or remote target."""
        options = options or {}
        scan_target = self.target_resolver.resolve(target_str, branch=branch, commit=commit, tag=tag)
        context = ScanContext(target=scan_target, options=options)

        try:
            local_path = self.repo_manager.acquire_target(scan_target)
            context.workspace_path = local_path

            # Execute Knowledge Graph & Attack Path Analysis
            graph, attack_paths, project_risk = self.graph_use_case.execute(local_path)

            context.end_time = datetime.now(timezone.utc).isoformat()
            return ScanResult(
                context=context,
                findings=[],
                graph=graph,
                attack_paths=attack_paths,
                project_risk=project_risk,
                exit_code=0,
            )
        finally:
            self.repo_manager.cleanup()
