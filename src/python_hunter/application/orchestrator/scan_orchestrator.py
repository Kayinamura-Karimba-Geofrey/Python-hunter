"""Scan Orchestrator implementation for Python Hunter."""

from datetime import datetime, timezone
from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_exploitability import AnalyzeExploitabilityUseCase
from python_hunter.application.use_cases.analyze_knowledge_graph import AnalyzeKnowledgeGraphUseCase
from python_hunter.application.orchestrator.scan_context import ScanContext, ScanResult
from python_hunter.domain.discovery.language_detector import LanguageDetector
from python_hunter.domain.language.registry import LanguageRegistry
from python_hunter.domain.malware.analyzers.polinrider_detector import PolinRiderDetector
from python_hunter.domain.malware.cleaners.polinrider_cleaner import PolinRiderCleaner
from python_hunter.infrastructure.repository.repository_manager import RepositoryManager
from python_hunter.infrastructure.repository.target_resolver import ScanTarget, TargetResolver


class ScanOrchestrator:
    """Coordinates target resolution, repository acquisition, language detection, knowledge graph construction, risk calculation, and report generation."""

    def __init__(self) -> None:
        self.target_resolver = TargetResolver()
        self.repo_manager = RepositoryManager()
        self.language_detector = LanguageDetector()
        self.language_registry = LanguageRegistry()
        self.graph_use_case = AnalyzeKnowledgeGraphUseCase()
        self.exploitability_use_case = AnalyzeExploitabilityUseCase()
        self.polinrider_detector = PolinRiderDetector()
        self.polinrider_cleaner = PolinRiderCleaner()

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

            # Detect Languages
            detected_langs = self.language_detector.detect_languages(local_path)
            context.options["detected_languages"] = [lang.value for lang in detected_langs]

            # Detect PolinRider / TasksJacker Malware
            malware_findings = self.polinrider_detector.detect(local_path)

            # Automated Cleanup if requested
            if options.get("clean", False):
                cleanup_result = self.polinrider_cleaner.clean(local_path)
                context.options["cleanup_result"] = cleanup_result

            # Execute Knowledge Graph & Attack Path Analysis
            graph, attack_paths, project_risk = self.graph_use_case.execute(local_path)

            if malware_findings and project_risk:
                project_risk.overall_score = max(project_risk.overall_score, 90.0)

            context.end_time = datetime.now(timezone.utc).isoformat()
            return ScanResult(
                context=context,
                findings=malware_findings,
                graph=graph,
                attack_paths=attack_paths,
                project_risk=project_risk,
                exit_code=1 if malware_findings else 0,
            )
        finally:
            self.repo_manager.cleanup()
