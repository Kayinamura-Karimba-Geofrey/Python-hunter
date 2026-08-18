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


from python_hunter.application.use_cases.analyze_callgraph import AnalyzeCallGraphUseCase
from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.application.use_cases.analyze_dynamic import AnalyzeDynamicUseCase
from python_hunter.application.use_cases.analyze_git import AnalyzeGitUseCase
from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase
from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase
from python_hunter.application.use_cases.analyze_vulnerabilities import AnalyzeVulnerabilitiesUseCase
from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.frameworks.detector import FrameworkDetector
from python_hunter.domain.frameworks.registry import FrameworkRegistry
from python_hunter.domain.policy.engine import SecurityPolicyEngine
import python_hunter.infrastructure.frameworks  # Ensures default framework adapters are registered


class AnalyzeSecurityUseCase:
    """Orchestrates Project Discovery -> AST Analysis -> Framework Intelligence -> Security Rules -> Taint -> Call Graph."""

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
        callgraph_use_case: AnalyzeCallGraphUseCase | None = None,
        dynamic_use_case: AnalyzeDynamicUseCase | None = None,
    ) -> None:
        self.discovery = discovery_use_case or DiscoverProjectUseCase()
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.rule_engine = rule_engine or SecurityRuleEngine(registry=get_default_registry())
        self.secrets_use_case = secrets_use_case or AnalyzeSecretsUseCase()
        self.dependencies_use_case = dependencies_use_case or AnalyzeDependenciesUseCase()
        self.vulnerabilities_use_case = vulnerabilities_use_case or AnalyzeVulnerabilitiesUseCase(offline=True)
        self.git_use_case = git_use_case or AnalyzeGitUseCase()
        self.taint_use_case = taint_use_case or AnalyzeTaintUseCase()
        self.callgraph_use_case = callgraph_use_case or AnalyzeCallGraphUseCase()
        self.dynamic_use_case = dynamic_use_case or AnalyzeDynamicUseCase()
        self.framework_detector = FrameworkDetector()

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

        # Framework Detection & Augmentation
        framework_profile = self.framework_detector.analyze(ast_summary.documents)
        context.metadata["framework_profile"] = framework_profile

        # Augment Taint Engine sources/sinks from detected framework adapters
        framework_findings: list[Finding] = []
        for adapter in FrameworkRegistry.list_adapters():
            extra_srcs = adapter.discover_sources(ast_summary.documents)
            extra_snks = adapter.discover_sinks(ast_summary.documents)
            self.taint_use_case.engine.config.sources.update(extra_srcs)
            self.taint_use_case.engine.config.sinks.update(extra_snks)
            rts = adapter.discover_routes(ast_summary.documents)
            framework_profile.routes.extend(rts)
            pattern_findings = adapter.analyze_framework_patterns(ast_summary.documents, framework_profile)
            framework_findings.extend(pattern_findings)

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

        # Run dynamic behavior analysis scan
        dynamic_behaviors, dynamic_summary = self.dynamic_use_case.execute(target_path)
        context.metadata["dynamic_summary"] = dynamic_summary
        self.callgraph_use_case.engine.add_dynamic_behaviors(dynamic_behaviors)

        # Run static taint dataflow analysis scan
        taint_result = self.taint_use_case.execute(target_path)
        taint_findings: list[Finding] = taint_result.get("findings", [])

        # Run interprocedural call graph & reachability scan
        callgraph_result = self.callgraph_use_case.execute(target_path)
        callgraph_findings: list[Finding] = callgraph_result.get("findings", [])

        raw_findings = (
            ast_findings
            + framework_findings
            + secret_findings
            + dep_findings
            + vuln_findings
            + git_findings
            + taint_findings
            + callgraph_findings
        )

        # 1. Correlate and deduplicate findings across engines
        correlator = FindingCorrelator()
        deduped_findings, attack_paths = correlator.correlate(
            raw_findings=raw_findings,
            callgraph_data=callgraph_result,
            taint_flows=taint_result.get("flows"),
            git_history=git_result.get("commits"),
        )

        # 2. Assign 0-100 Risk Scores
        risk_engine = RiskEngine()
        risk_engine.score_findings(deduped_findings)

        # 3. Evaluate Security Policy & Gate
        policy_engine = SecurityPolicyEngine.from_config_file(
            f"{target_path}/pyh_policy.yml" if target_path.endswith("/") else f"{target_path}/pyh_policy.yml"
        )

        posture = risk_engine.calculate_posture(deduped_findings, attack_paths)
        policy_passed, violations = policy_engine.evaluate(deduped_findings, posture.project_risk_score)
        posture.policy_passed = policy_passed
        posture.policy_violations = violations

        return deduped_findings, ast_summary, rule_results
