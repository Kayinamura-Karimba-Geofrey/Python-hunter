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


from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.application.use_cases.analyze_git import AnalyzeGitUseCase
from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase
from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase
from python_hunter.application.use_cases.analyze_vulnerabilities import AnalyzeVulnerabilitiesUseCase


class AnalyzeSecurityUseCase:
    """Orchestrates Project Discovery -> AST Analysis -> Security Rule Engine -> Secret Detection -> Dependency Analysis -> Vulnerability Intelligence -> Git Analysis -> Taint Analysis."""

    def __init__(
        self,
        discovery_use_case: DiscoverProjectUseCase | None = None,
        ast_use_case: AnalyzeASTUseCase | None = None,
        rule_engine: SecurityRuleEngine | None = None,
        secrets_use_case: AnalyzeSecretsUseCase | None = None,
        dependencies_use_case: AnalyzeDependenciesUseCase | None = None,
        vulnerabilities_use_case: AnalyzeVulnerabilitiesUseCase | None = None,
        git_use_case: AnalyzeGitUseCase | None = None,
        taint_use_case: AnalyzeTaintUseCase | None = None,
    ) -> None:
        self.discovery = discovery_use_case or DiscoverProjectUseCase()
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.rule_engine = rule_engine or SecurityRuleEngine(registry=get_default_registry())
        self.secrets_use_case = secrets_use_case or AnalyzeSecretsUseCase()
        self.dependencies_use_case = dependencies_use_case or AnalyzeDependenciesUseCase()
        self.vulnerabilities_use_case = vulnerabilities_use_case or AnalyzeVulnerabilitiesUseCase(offline=True)
        self.git_use_case = git_use_case or AnalyzeGitUseCase()
        self.taint_use_case = taint_use_case or AnalyzeTaintUseCase()

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

        ast_findings, rule_results = self.rule_engine.evaluate_rules(ast_summary, context)

        # Run secret detection scan
        secrets_result = self.secrets_use_case.execute(target_path)
        secret_findings: list[Finding] = secrets_result.get("findings", [])

        # Run dependency analysis scan
        dep_result = self.dependencies_use_case.execute(target_path)
        dep_findings: list[Finding] = dep_result.get("findings", [])

        # Run vulnerability intelligence scan
        vuln_result = self.vulnerabilities_use_case.execute(target_path)
        vuln_findings: list[Finding] = vuln_result.get("findings", [])

        # Run git repository analysis scan
        git_result = self.git_use_case.execute(target_path)
        git_findings: list[Finding] = git_result.get("findings", [])

        # Run static taint dataflow analysis scan
        taint_result = self.taint_use_case.execute(target_path)
        taint_findings: list[Finding] = taint_result.get("findings", [])

        # Deduplicate combined findings
        combined: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for f in ast_findings + secret_findings + dep_findings + vuln_findings + git_findings + taint_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                combined.append(f)

        return combined, ast_summary, rule_results
