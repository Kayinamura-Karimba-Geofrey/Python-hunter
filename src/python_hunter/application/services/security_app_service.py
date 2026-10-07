"""Unified SecurityApplicationService providing domain intelligence for REST API and CLI."""

import uuid
from datetime import UTC, datetime
from typing import Any

from python_hunter import __version__
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.application.services import workspace_scans
from python_hunter.application.services.scan_queries import ScanQueryService, build_scan_record

# Step 45: Advanced AI Security Intelligence & Autonomous Security Analysis
from python_hunter.domain.ai import (
    AISecurityIntelligenceEngine,
)
from python_hunter.domain.common.enums import (
    VerificationMode,
)

# Step 46: Enterprise Compliance, Governance & Security Assurance
from python_hunter.domain.compliance import ComplianceEngine as EnterpriseComplianceEngine
from python_hunter.domain.correlation.attack_path_engine import WhatIfAnalyzer
from python_hunter.domain.dependencies.polyglot_dependency_adapter import PolyglotDependencyAdapter
from python_hunter.domain.frameworks.framework_registry import FrameworkRegistry
from python_hunter.domain.github.github_app import GitHubAppIntegration
from python_hunter.domain.github.github_checks_service import (
    GitHubChecksService,
    GitHubCommentService,
)
from python_hunter.domain.github.pr_security_engine import PullRequestSecurityEngine
from python_hunter.domain.github.webhook_handler import GitHubWebhookHandler
from python_hunter.domain.github.webhook_queue import GitHubWebhookEventQueue
from python_hunter.domain.governance.auth import User
from python_hunter.domain.governance.compliance import (
    ComplianceEngine,
)
from python_hunter.domain.governance.engine import (
    GovernanceEngine,
)
from python_hunter.domain.governance.rbac import (
    RBACEngine,
    Team,
)

# Step 42: Enterprise Multi-Tenancy & Governance
from python_hunter.domain.governance.tenant import (
    Organization,
    Project,
)
from python_hunter.domain.graph.engine import SecurityKnowledgeGraphEngine
from python_hunter.domain.history.history_engine import SecurityHistoryStore, SnapshotComparator
from python_hunter.domain.integrations.engine import (
    IntegrationEngine,
)

# Step 43: Enterprise Integrations & Security Ecosystem
from python_hunter.domain.integrations.models import (
    Integration,
    IntegrationProviderType,
    IntegrationStatus,
)
from python_hunter.domain.intelligence.engine import SecurityIntelligenceEngine
from python_hunter.domain.intelligence.posture import SecurityPostureTracker
from python_hunter.domain.intelligence.remediation import RemediationQueueManager
from python_hunter.domain.intelligence.source import IntelligenceSourceRegistry

# Step 47: Advanced Multi-Language Security Analysis Platform
from python_hunter.domain.language import PolyglotSecurityAnalysisEngine
from python_hunter.domain.language.analyzer import AnalyzerRegistry
from python_hunter.domain.language.detector import LanguageDetector
from python_hunter.domain.language.models import Language
from python_hunter.domain.language.registry import LanguageRegistry
from python_hunter.domain.operations.alerts import AlertEngine

# Step 41: Autonomous Security Operations
from python_hunter.domain.operations.events import (
    SecurityEventBus,
)
from python_hunter.domain.operations.health import SecurityPlatformHealth
from python_hunter.domain.operations.incidents import IncidentCorrelationEngine
from python_hunter.domain.operations.incremental import ChangeImpactEngine, SecurityDriftEngine
from python_hunter.domain.operations.notifications import (
    MockSlackNotificationProvider,
    NotificationRegistry,
)
from python_hunter.domain.operations.queue import (
    SecurityJobQueue,
    SecurityWorker,
)
from python_hunter.domain.operations.scheduler import SecurityScheduler
from python_hunter.domain.policy.policy_evaluator import PolicyEngine
from python_hunter.domain.rules.polyglot_rule_registry import PolyglotRuleRegistry

# Step 48: Threat Intelligence & Security Research Platform
from python_hunter.domain.threat_intel import ThreatIntelligenceEngine
from python_hunter.domain.verification.engine import VerificationEngine
from python_hunter.domain.verification.models import VerificationAuthorization, VerificationResult
from python_hunter.infrastructure.governance.configuration import ConfigurationManager
from python_hunter.infrastructure.governance.feature_flags import FeatureFlagService
from python_hunter.infrastructure.intelligence.db import (
    LocalIntelligenceDatabase,
    OSVIntelligenceSource,
)
from python_hunter.infrastructure.operations.webhooks import AuditLogger, GitHubWebhookValidator
from python_hunter.infrastructure.scaling.bulkhead import BulkheadManager
from python_hunter.infrastructure.scaling.distributed_queue import (
    PriorityJobQueue,
)
from python_hunter.infrastructure.scaling.locks import LockManager

# Step 44: Distributed Architecture, Scalability & Production Hardening
from python_hunter.infrastructure.scaling.quotas import QuotaManager
from python_hunter.infrastructure.scaling.sandboxing import ScannerSandbox
from python_hunter.infrastructure.storage.cache import CacheAbstraction
from python_hunter.infrastructure.storage.object_storage import LocalObjectStorage
from python_hunter.infrastructure.storage.scan_store import ScanResultStore
from python_hunter.infrastructure.storage.search import ScalableSearchEngine
from python_hunter.infrastructure.telemetry.health import DependencyHealthStatus
from python_hunter.infrastructure.telemetry.logging import StructuredLogger
from python_hunter.infrastructure.telemetry.metrics import MetricsCollector


class SecurityApplicationService:
    """Unified application service wrapping scanning, policy evaluation, multi-language engine, intelligence platform, continuous operations, enterprise governance, enterprise integrations, and distributed production hardening."""

    def __init__(self, store: ScanResultStore | None = None) -> None:
        self.orchestrator = ScanOrchestrator()
        self.policy_engine = PolicyEngine()
        self.store = store or ScanResultStore()
        self.queries = ScanQueryService(self.store, self.policy_engine)
        self.history_store = SecurityHistoryStore()
        self.comparator = SnapshotComparator()
        self.github_app = GitHubAppIntegration()
        self.webhook_handler = GitHubWebhookHandler()
        self.webhook_queue = GitHubWebhookEventQueue()
        self.pr_engine = PullRequestSecurityEngine()
        self.checks_service = GitHubChecksService()
        self.comment_service = GitHubCommentService()
        self.language_registry = LanguageRegistry()
        self.language_detector = LanguageDetector()
        self.framework_registry = FrameworkRegistry()
        self.rule_registry = PolyglotRuleRegistry()
        self.dependency_adapter = PolyglotDependencyAdapter()
        self.graph_engine = SecurityKnowledgeGraphEngine()
        self.verification_engine = VerificationEngine()
        self._authorizations: list[VerificationAuthorization] = []

        # Step 40: Security Intelligence Engine
        self.intel_registry = IntelligenceSourceRegistry()
        self.intel_registry.register(OSVIntelligenceSource())
        self.intel_engine = SecurityIntelligenceEngine(registry=self.intel_registry)
        self.posture_tracker = SecurityPostureTracker()
        self.remediation_queue = RemediationQueueManager()
        self.intel_db = LocalIntelligenceDatabase()

        self.event_bus = SecurityEventBus()
        self.job_queue = SecurityJobQueue()
        self.worker = SecurityWorker(self.job_queue)
        self.impact_engine = ChangeImpactEngine()
        self.drift_engine = SecurityDriftEngine()
        self.alert_engine = AlertEngine()
        self.notification_registry = NotificationRegistry()
        self.notification_registry.register(MockSlackNotificationProvider())
        self.incident_engine = IncidentCorrelationEngine()
        self.scheduler = SecurityScheduler()
        self.health_monitor = SecurityPlatformHealth()
        self.webhook_validator = GitHubWebhookValidator()
        self.audit_logger = AuditLogger()

        # Step 42: Enterprise Multi-Tenancy & Governance
        self.rbac_engine = RBACEngine()
        self.governance_engine = GovernanceEngine()
        self.compliance_engine = ComplianceEngine()
        self.organizations: dict[str, Organization] = {
            "org-default": Organization(organization_id="org-default", name="Default Organization", slug="default-org")
        }
        self.users: dict[str, User] = {
            "usr-admin": User(
                user_id="usr-admin",
                email="admin@pythonhunter.io",
                display_name="Security Admin",
                # No local password: API login is configured via PYH_API_USERNAME/PYH_API_PASSWORD_HASH.
                password_hash="",
            )
        }
        self.teams: dict[str, Team] = {
            "team-sec": Team(team_id="team-sec", organization_id="org-default", name="Security Team")
        }
        self.projects: dict[str, Project] = {
            "proj-core": Project(
                project_id="proj-core",
                organization_id="org-default",
                name="Python Hunter Platform",
                owner_team_id="team-sec",
            )
        }

        # Step 43: Enterprise Integrations & Security Ecosystem
        self.integration_engine = IntegrationEngine()
        default_github_integration = Integration(
            integration_id="int-github-default",
            organization_id="org-default",
            provider=IntegrationProviderType.GITHUB,
            name="GitHub Main App",
            status=IntegrationStatus.HEALTHY,
        )
        self.integration_engine.register_integration(default_github_integration)

        # Step 44: Distributed Architecture, Scalability & Hardening
        self.quota_manager = QuotaManager()
        self.priority_queue = PriorityJobQueue()
        self.lock_manager = LockManager()
        self.bulkhead_manager = BulkheadManager()
        self.sandbox = ScannerSandbox()
        self.cache = CacheAbstraction()
        self.object_storage = LocalObjectStorage()
        self.search_engine = ScalableSearchEngine()

        # Step 45: AI Security Intelligence Engine
        self.ai_engine = AISecurityIntelligenceEngine()

        # Step 46: Enterprise Compliance & Governance Engine
        self.enterprise_compliance_engine = EnterpriseComplianceEngine()

        # Step 47: Polyglot Security Analysis Engine
        self.polyglot_engine = PolyglotSecurityAnalysisEngine()

        # Step 48: Threat Intelligence Engine
        self.threat_intel_engine = ThreatIntelligenceEngine()




        self.structured_logger = StructuredLogger()
        self.metrics_collector = MetricsCollector()
        self.dependency_health = DependencyHealthStatus()
        self.feature_flags = FeatureFlagService()
        self.config_manager = ConfigurationManager()
        self.analyzer_registry = AnalyzerRegistry()

    def authorize_verification_target(
        self, target: str, authorized_by: str = "security_operator", valid_minutes: int = 60
    ) -> VerificationAuthorization:
        """Grants temporary authorization for active verification of a local target."""
        auth = VerificationAuthorization.create_temporary_authorization(
            target=target, authorized_by=authorized_by, valid_minutes=valid_minutes
        )
        self._authorizations.append(auth)
        return auth

    def verify_finding(
        self,
        finding_id: str,
        active: bool = False,
        target: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Executes passive or active controlled verification for a specific finding."""
        finding = self.get_finding(finding_id)
        if finding is None:
            raise LookupError(f"Finding '{finding_id}' not found in the latest recorded scan.")

        mode = VerificationMode.ACTIVE if active else VerificationMode.PASSIVE
        active_auth = next((a for a in self._authorizations if a.is_valid and (not target or a.target == target)), None)

        res: VerificationResult = self.verification_engine.verify_finding(
            finding=finding,
            mode=mode,
            authorization=active_auth,
            target=target,
            dry_run=dry_run,
        )

        return {
            "finding_id": res.finding_id,
            "verification_status": res.verification_status.value,
            "confidence": res.confidence.value,
            "evidence": res.evidence,
            "test_method": res.test_method,
            "timestamp": res.timestamp,
            "environment": res.environment,
            "safety_level": res.safety_level.value,
            "execution_time_ms": res.execution_time_ms,
            "test_hash": res.test_hash,
            "tamper_proof_signature": res.tamper_proof_signature,
        }

    def simulate_remediation(self, workspace_path: str, remediated_finding_ids: list[str]) -> dict[str, Any]:
        """Runs what-if simulation to project residual attack paths and risk score reduction."""
        graph, _paths, _clusters = self.graph_engine.synthesize_cross_domain_graph(
            sast_findings=self.list_findings(),
            sca_findings=self.list_dependencies(),
            infrastructure_resources=[],
        )
        return WhatIfAnalyzer.simulate_remediation(graph, self.graph_engine.attack_path_engine, remediated_finding_ids)

    def get_system_info(self) -> dict[str, Any]:
        return {
            "name": "Python Hunter Security Platform",
            "version": __version__,
            "supported_languages": [m.display_name for m in self.language_registry.list_metadata()],
            "supported_frameworks": [f.name for f in self.framework_registry.list_frameworks()],
            "status": "OPERATIONAL",
        }

    # Read-side views, all derived from persisted scan records (see scan_queries.py).

    def get_dashboard_summary(self) -> dict[str, Any]:
        return self.queries.get_dashboard_summary()

    def list_repositories(self) -> list[dict[str, Any]]:
        return self.queries.list_repositories()

    def list_findings(
        self,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.queries.list_findings(severity=severity, status=status, search=search)

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return self.queries.get_finding(finding_id)

    def list_attack_paths(self) -> list[dict[str, Any]]:
        return self.queries.list_attack_paths()

    def list_dependencies(self) -> list[dict[str, Any]]:
        return self.queries.list_dependencies()

    def list_services(self) -> list[dict[str, Any]]:
        """Service inventory is not persisted by scans yet, so there is nothing to report."""
        return []

    def list_apis(self) -> list[dict[str, Any]]:
        """API endpoint inventory is not persisted by scans yet, so there is nothing to report."""
        return []

    def list_history(self) -> list[dict[str, Any]]:
        return self.queries.list_history()

    def list_regressions(self) -> list[dict[str, Any]]:
        return self.queries.list_regressions()

    def list_policies(self) -> list[dict[str, Any]]:
        return self.queries.list_policies()

    def list_compliance(self) -> list[dict[str, Any]]:
        return self.queries.list_compliance()

    def list_reports(self) -> list[dict[str, Any]]:
        return self.queries.list_reports()

    def list_audit_logs(self) -> list[dict[str, Any]]:
        return self.store.list_audit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        return self.store.get_scan(scan_id)

    def execute_scan(
        self,
        target_path: str,
        profile: str = "strict",
        scan_id: str | None = None,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Run a full scan, persist its record, and return a summary."""
        scan_id = scan_id or str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        scan_result = self.orchestrator.run_scan(target_path)
        risk_score = float(scan_result.project_risk.overall_score) if scan_result.project_risk else 0.0
        gate_result = self.policy_engine.evaluate_gate(scan_result.findings, risk_score=risk_score, profile=profile)

        record = build_scan_record(scan_id, target_path, profile, scan_result, gate_result, created_at)
        self.store.save_scan(record)
        self.store.append_audit("SCAN_EXECUTED", actor, target_path, "SUCCESS")

        return {
            "scan_id": scan_id,
            "target": target_path,
            "findings_count": record["findings_count"],
            "risk_score": risk_score,
            "gate_status": gate_result.status.value,
            "violations": gate_result.violations,
            "exit_code": gate_result.exit_code,
        }

    def list_github_installations(self) -> list[dict[str, Any]]:
        return self.store.list_installations()

    def get_webhook_status(self) -> dict[str, Any]:
        return self.webhook_queue.get_status_summary()

    def process_github_webhook(
        self, raw_body: bytes, signature_header: str | None, delivery_id: str | None, event_type: str
    ) -> dict[str, Any]:
        parse_res = self.webhook_handler.parse_event(raw_body, signature_header, delivery_id, event_type)
        if parse_res.get("status") == "ACCEPTED":
            self._record_installation(parse_res["payload"])
            job = self.webhook_queue.enqueue_event(
                delivery_id=delivery_id or "deliv-anon",
                event_type=event_type,
                payload=parse_res["payload"],
            )
            self.webhook_queue.process_next(self._handle_queued_webhook_job)
            return {
                "status": "ACCEPTED",
                "job_id": job.job_id,
                "message": f"Webhook {event_type} event enqueued successfully.",
            }
        return parse_res

    def _record_installation(self, payload: dict[str, Any]) -> None:
        installation = payload.get("installation") or {}
        if not installation.get("id"):
            return
        inst_id = str(installation["id"])
        existing = self.store.get_installation(inst_id) or {
            "installation_id": inst_id,
            "organization": (installation.get("account") or {}).get("login", ""),
            "repositories": [],
            "permissions": sorted((installation.get("permissions") or {}).keys()),
            "status": "ACTIVE",
            "installed_at": datetime.now(UTC).isoformat(),
        }
        repo = (payload.get("repository") or {}).get("full_name")
        if repo and repo not in existing["repositories"]:
            existing["repositories"].append(repo)
        if payload.get("action") == "deleted":
            existing["status"] = "REMOVED"
        self.store.save_installation(existing)

    def _handle_queued_webhook_job(self, job: Any) -> None:
        if job.event_type != "pull_request":
            return
        pr_data = job.payload.get("pull_request", {})
        repo = job.payload.get("repository", {}).get("full_name", "")
        pr_num = pr_data.get("number") or job.payload.get("number")
        if not repo or not pr_num:
            return
        self.run_pull_request_analysis(
            repo,
            int(pr_num),
            pr_data.get("base", {}).get("sha", ""),
            pr_data.get("head", {}).get("sha", ""),
            pr_info={
                "title": pr_data.get("title", f"Pull Request #{pr_num}"),
                "author": (pr_data.get("user") or {}).get("login", ""),
                "base_branch": pr_data.get("base", {}).get("ref", ""),
                "head_branch": pr_data.get("head", {}).get("ref", ""),
            },
        )

    def list_pull_requests(self) -> list[dict[str, Any]]:
        fields = (
            "pr_id", "pr_number", "repository", "title", "author", "base_branch", "head_branch",
            "head_sha", "status", "security_score", "score_delta", "risk_level", "policy_result",
            "new_vulnerabilities_count", "fixed_vulnerabilities_count", "new_attack_paths_count",
            "dependency_regressions_count", "secrets_found_count", "updated_at",
        )
        return [{k: pr.get(k) for k in fields} for pr in self.store.list_pull_requests()]

    def get_pull_request_detail(self, pr_id: str) -> dict[str, Any] | None:
        pr = self.store.get_pull_request(pr_id)
        if pr is None:
            pr = next(
                (p for p in self.store.list_pull_requests() if str(p.get("pr_number")) == pr_id), None
            )
        return pr

    def run_pull_request_analysis(
        self,
        repository: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        base_findings: list[dict[str, Any]] | None = None,
        head_findings: list[dict[str, Any]] | None = None,
        changed_files: list[str] | None = None,
        pr_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare BASE and HEAD findings for a pull request and persist the outcome."""
        res = self.pr_engine.analyze_pull_request(
            pr_number=pr_number,
            repository=repository,
            base_sha=base_sha,
            head_sha=head_sha,
            base_findings=base_findings or [],
            head_findings=head_findings or [],
            base_attack_paths=[],
            head_attack_paths=[],
            changed_files=changed_files or [],
            base_dependencies=[],
            head_dependencies=[],
        )

        pr_id = f"pr-{repository.replace('/', '-')}-{pr_number}"
        info = {"id": pr_id, "number": pr_number, "repository": repository, **(pr_info or {})}
        summary = self.pr_engine.generate_summary(res, info)
        check_run = self.checks_service.build_check_run(res, summary)
        pr_comment = self.comment_service.post_or_update_pr_comment(repository, pr_number, summary.summary_markdown)

        now = datetime.now(UTC).isoformat()
        previous = self.store.get_pull_request(pr_id)
        timeline = list(previous.get("timeline", [])) if previous else []
        timeline.append(
            {
                "event": "POLICY_EVALUATED",
                "timestamp": now,
                "details": f"Head {head_sha[:7]} evaluated: {summary.policy_result.value}.",
            }
        )
        self.store.save_pull_request(
            {
                "pr_id": pr_id,
                "pr_number": pr_number,
                "repository": repository,
                "title": summary.title,
                "author": summary.author,
                "base_branch": summary.base_branch,
                "head_branch": summary.head_branch,
                "head_sha": head_sha,
                "status": "OPEN",
                "security_score": summary.security_score,
                "score_delta": summary.score_delta,
                "risk_level": summary.risk_level,
                "policy_result": summary.policy_result.value,
                "new_vulnerabilities_count": summary.new_vulnerabilities_count,
                "fixed_vulnerabilities_count": summary.fixed_vulnerabilities_count,
                "new_attack_paths_count": summary.new_attack_paths_count,
                "dependency_regressions_count": summary.dependency_regressions_count,
                "secrets_found_count": summary.secrets_found_count,
                "updated_at": now,
                "changed_files": res.changed_files,
                "security_relevant_files": res.security_relevant_files,
                "new_findings": res.new_findings,
                "fixed_findings": res.fixed_findings,
                "new_attack_paths": res.new_attack_paths,
                "fixed_attack_paths": res.fixed_attack_paths,
                "dependency_regressions": res.dependency_regressions,
                "secret_regressions": res.secret_regressions,
                "timeline": timeline,
            }
        )

        return {
            "result": res,
            "summary": summary,
            "check_run": check_run,
            "comment": pr_comment,
        }

    def list_languages(self, language_filter: str | None = None) -> list[dict[str, Any]]:
        metadatas = self.language_registry.list_metadata()
        if language_filter:
            metadatas = [m for m in metadatas if m.language.value.lower() == language_filter.lower() or language_filter.lower() in m.aliases]
        return [
            {
                "language": m.language.value,
                "display_name": m.display_name,
                "aliases": m.aliases,
                "file_extensions": m.file_extensions,
                "parser": m.parser,
                "analyzer": m.analyzer,
                "framework_adapters": m.framework_adapters,
                "dependency_ecosystem": m.dependency_ecosystem,
                "capabilities": m.capabilities.to_dict(),
                "version": m.version,
            }
            for m in metadatas
        ]

    def list_frameworks(self, language_filter: str | None = None) -> list[dict[str, Any]]:
        lang_enum = None
        if language_filter:
            try:
                lang_enum = Language(language_filter.lower())
            except ValueError:
                pass
        frameworks = self.framework_registry.list_frameworks(lang_enum)
        return [
            {
                "name": fw.name,
                "display_name": fw.display_name,
                "language": fw.language.value,
                "category": fw.category,
                "description": fw.description,
                "version": fw.version,
            }
            for fw in frameworks
        ]

    def get_repository_language_profile(self, workspace_path: str) -> dict[str, Any]:
        profile = self.language_detector.detect_workspace_languages(workspace_path)
        return {
            "total_files": profile.total_files,
            "total_lines": profile.total_lines,
            "percentage_by_files": profile.percentage_by_files,
            "percentage_by_lines": profile.percentage_by_lines,
            "detected_manifests": profile.detected_manifests,
        }

    def scan_polyglot_workspace(
        self,
        workspace_path: str,
        selected_languages: list[str] | None = None,
        selected_frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        profile = self.language_detector.detect_workspace_languages(workspace_path)
        active_adapters = self.language_registry.discover_active_adapters(workspace_path)

        if selected_languages:
            filter_set = {s.lower() for s in selected_languages}
            active_adapters = [a for a in active_adapters if a.language.value in filter_set or any(alias in filter_set for alias in a.metadata.aliases)]

        all_findings = []
        for adapter in active_adapters:
            findings = adapter.analyze(workspace_path)
            all_findings.extend(findings)

        dependencies = self.dependency_adapter.parse_workspace_dependencies(workspace_path)
        dep_dicts = [
            {
                "package_name": d.package_name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "language": d.language.value,
                "vulnerability_status": d.vulnerability_status,
            }
            for d in dependencies
        ]

        return {
            "workspace_path": workspace_path,
            "profile": {
                "total_files": profile.total_files,
                "total_lines": profile.total_lines,
                "percentage_by_lines": profile.percentage_by_lines,
            },
            "active_languages": [a.language.value for a in active_adapters],
            "total_findings": len(all_findings),
            "findings": all_findings,
            "dependencies_count": len(dep_dicts),
            "dependencies": dep_dicts,
        }

    def execute_interprocedural_scan(self, workspace_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Performs interprocedural SAST analysis across functions, files, modules, and services."""
        return workspace_scans.execute_interprocedural_scan(workspace_path, options)

    def execute_sca_scan(self, workspace_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Performs SCA, dependency graphing, reachability, and license policy checks."""
        return workspace_scans.execute_sca_scan(workspace_path, options)

    def execute_secrets_scan(
        self, workspace_path: str, scan_history: bool = False, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Scans workspace files, and optionally Git history, for credential leaks."""
        return workspace_scans.execute_secrets_scan(workspace_path, scan_history, options)

    def execute_infrastructure_scan(self, workspace_path: str) -> dict[str, Any]:
        """Scans workspace for Docker, Kubernetes, Terraform, and CI/CD security issues."""
        return workspace_scans.execute_infrastructure_scan(workspace_path)
