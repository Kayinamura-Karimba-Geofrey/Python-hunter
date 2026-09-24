"""Scan Orchestrator implementation for Python Hunter."""

from datetime import datetime, timezone
from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.application.use_cases.analyze_exploitability import AnalyzeExploitabilityUseCase
from python_hunter.application.use_cases.analyze_knowledge_graph import AnalyzeKnowledgeGraphUseCase
from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase
from python_hunter.application.use_cases.analyze_vulnerabilities import AnalyzeVulnerabilitiesUseCase
from python_hunter.application.orchestrator.scan_context import ScanContext, ScanResult
from python_hunter.domain.dependencies.npm_supply_chain import NPMSupplyChainAnalyzer
from python_hunter.domain.dependencies.pypi_supply_chain import PyPISupplyChainAnalyzer
from python_hunter.domain.discovery.language_detector import LanguageDetector
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.language.registry import LanguageRegistry
from python_hunter.domain.malware.analyzers.polinrider_detector import PolinRiderDetector
from python_hunter.domain.malware.cleaners.polinrider_cleaner import PolinRiderCleaner
from python_hunter.infrastructure.repository.repository_manager import RepositoryManager
from python_hunter.infrastructure.repository.target_resolver import ScanTarget, TargetResolver


class ScanOrchestrator:
    """Coordinates target resolution, repository acquisition, language detection, SAST, secrets, SCA, malware, risk calculation, and report generation."""

    def __init__(self) -> None:
        self.target_resolver = TargetResolver()
        self.repo_manager = RepositoryManager()
        self.language_detector = LanguageDetector()
        self.language_registry = LanguageRegistry()
        self.graph_use_case = AnalyzeKnowledgeGraphUseCase()
        self.exploitability_use_case = AnalyzeExploitabilityUseCase()
        self.polinrider_detector = PolinRiderDetector()
        self.polinrider_cleaner = PolinRiderCleaner()
        self.npm_supply_chain = NPMSupplyChainAnalyzer()
        self.pypi_supply_chain = PyPISupplyChainAnalyzer()
        self.secrets_use_case = AnalyzeSecretsUseCase()
        self.dependencies_use_case = AnalyzeDependenciesUseCase()
        self.vulnerabilities_use_case = AnalyzeVulnerabilitiesUseCase(offline=True)

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
            local_path = self.repo_manager.acquire_target(
                scan_target,
                timeout=options.get("timeout"),
                idle_timeout=options.get("idle_timeout"),
            )
            context.workspace_path = local_path

            # Detect Languages
            detected_langs = self.language_detector.detect_languages(local_path)
            context.options["detected_languages"] = [lang.value for lang in detected_langs]

            # 1. Detect PolinRider / TasksJacker Malware
            malware_findings = self.polinrider_detector.detect(local_path)

            # Automated Cleanup if requested
            if options.get("clean", False):
                cleanup_result = self.polinrider_cleaner.clean(local_path)
                context.options["cleanup_result"] = cleanup_result

            # 2. Analyze NPM Supply Chain
            npm_findings = self.npm_supply_chain.analyze_workspace(local_path)

            # 3. Analyze PyPI Supply Chain
            pypi_findings = self.pypi_supply_chain.analyze_workspace(local_path)

            # 4. Scan Secrets
            secret_findings = self._scan_secrets(local_path, options)

            # 5. Scan SCA Dependencies & Vulnerabilities
            sca_findings = self._scan_dependencies(local_path, options)

            # Aggregate all multi-domain findings
            raw_findings = (
                malware_findings
                + npm_findings
                + pypi_findings
                + secret_findings
                + sca_findings
            )
            all_findings = self._deduplicate_findings(raw_findings)

            # Execute Knowledge Graph & Attack Path Analysis
            graph, attack_paths, project_risk = self.graph_use_case.execute(local_path)

            if all_findings and project_risk:
                has_critical = any(f.severity.value == "CRITICAL" for f in all_findings)
                has_high = any(f.severity.value == "HIGH" for f in all_findings)
                has_medium = any(f.severity.value == "MEDIUM" for f in all_findings)
                if has_critical or has_high:
                    project_risk.overall_score = max(project_risk.overall_score, 90.0)
                elif has_medium:
                    project_risk.overall_score = max(project_risk.overall_score, 50.0)
                else:
                    project_risk.overall_score = max(project_risk.overall_score, 20.0)

            context.end_time = datetime.now(timezone.utc).isoformat()
            has_violations = any(f.severity.value in ("CRITICAL", "HIGH") for f in all_findings)
            return ScanResult(
                context=context,
                findings=all_findings,
                graph=graph,
                attack_paths=attack_paths,
                project_risk=project_risk,
                exit_code=1 if has_violations else 0,
            )
        finally:
            self.repo_manager.cleanup()

    def _scan_secrets(self, local_path: str, options: dict[str, Any]) -> list[Finding]:
        """Executes secret scanning unless explicitly disabled."""
        if options.get("no_secrets", False):
            return []
        try:
            res = self.secrets_use_case.execute(local_path)
            return res.get("findings", [])
        except Exception:
            return []

    def _scan_dependencies(self, local_path: str, options: dict[str, Any]) -> list[Finding]:
        """Executes SCA dependency policy evaluation and vulnerability matching."""
        if options.get("no_dependencies", False) or options.get("no_sca", False):
            return []
        findings: list[Finding] = []
        try:
            dep_res = self.dependencies_use_case.execute(local_path)
            findings.extend(dep_res.get("findings", []))
        except Exception:
            pass

        try:
            vuln_res = self.vulnerabilities_use_case.execute(local_path)
            findings.extend(vuln_res.get("findings", []))
        except Exception:
            pass

        return findings

    @staticmethod
    def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
        """Deduplicates findings based on rule ID, file location, and evidence."""
        seen: set[tuple[str, str, int, str]] = set()
        deduped: list[Finding] = []
        for f in findings:
            line = f.location.line_start if f.location else 0
            key = (f.rule_id, f.file_path, line, f.evidence)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
