"""Analyze Security Application Use Case."""

import uuid
from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.projects.project import Project
from python_hunter.domain.rules.engine import SecurityRuleEngine
from python_hunter.domain.rules.models import RuleResult
from python_hunter.rules.ast import get_default_registry


class AnalyzeSecurityUseCase:
    """Orchestrates Project Discovery -> AST Analysis -> Security Rule Engine evaluation."""

    def __init__(
        self,
        discovery_use_case: DiscoverProjectUseCase | None = None,
        ast_use_case: AnalyzeASTUseCase | None = None,
        rule_engine: SecurityRuleEngine | None = None,
    ) -> None:
        self.discovery = discovery_use_case or DiscoverProjectUseCase()
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.rule_engine = rule_engine or SecurityRuleEngine(registry=get_default_registry())

    def execute(self, target_path: str) -> tuple[list[Finding], ASTAnalysisSummary, list[RuleResult]]:
        """Execute full security analysis flow on target path."""
        manifest = self.discovery.discover(target_path)
        ast_summary = self.ast_use_case.execute(target_path)

        project = Project(name=manifest.project_name, root_path=manifest.root_path)
        context = AnalysisContext(
            scan_id=str(uuid.uuid4()),
            project=project,
            target_files=[],
        )

        findings, rule_results = self.rule_engine.evaluate_rules(ast_summary, context)
        return findings, ast_summary, rule_results
