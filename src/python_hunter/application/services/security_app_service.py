"""Unified SecurityApplicationService providing domain intelligence for REST API and CLI."""

import uuid
from datetime import datetime, timezone
from typing import Any

from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.domain.history.history_engine import SecurityHistoryStore, SnapshotComparator
from python_hunter.domain.policy.policy_evaluator import PolicyEngine
from python_hunter.domain.github.github_app import GitHubAppIntegration
from python_hunter.domain.github.webhook_handler import GitHubWebhookHandler
from python_hunter.domain.github.webhook_queue import GitHubWebhookEventQueue
from python_hunter.domain.github.pr_security_engine import PullRequestSecurityEngine
from python_hunter.domain.github.github_checks_service import GitHubChecksService, GitHubCommentService
from python_hunter.domain.language.registry import LanguageRegistry
from python_hunter.domain.language.detector import LanguageDetector, LanguageProfile
from python_hunter.domain.language.models import Language
from python_hunter.domain.frameworks.framework_registry import FrameworkRegistry
from python_hunter.domain.dependencies.polyglot_dependency_adapter import PolyglotDependencyAdapter
from python_hunter.domain.rules.polyglot_rule_registry import PolyglotRuleRegistry
from python_hunter.domain.graph.engine import SecurityKnowledgeGraphEngine
from python_hunter.domain.correlation.attack_path_engine import WhatIfAnalyzer, AttackPathEngine
from python_hunter.domain.verification.engine import VerificationEngine
from python_hunter.domain.verification.models import VerificationAuthorization, VerificationResult
from python_hunter.domain.common.enums import VerificationMode, VerificationStatus, VerificationConfidence
from python_hunter.domain.intelligence.engine import SecurityIntelligenceEngine
from python_hunter.domain.intelligence.source import IntelligenceSourceRegistry
from python_hunter.domain.intelligence.posture import SecurityPostureTracker
from python_hunter.domain.intelligence.remediation import RemediationQueueManager, RemediationItem
from python_hunter.infrastructure.intelligence.db import OSVIntelligenceSource, LocalIntelligenceDatabase

# Step 41: Autonomous Security Operations
from python_hunter.domain.operations.events import SecurityEventBus, SecurityEvent, SecurityEventType
from python_hunter.domain.operations.queue import SecurityJobQueue, SecurityWorker, JobType, JobStatus
from python_hunter.domain.operations.incremental import ChangeImpactEngine, SecurityDriftEngine
from python_hunter.domain.operations.alerts import AlertEngine, SecurityAlert, AlertType
from python_hunter.domain.operations.notifications import NotificationRegistry, MockSlackNotificationProvider
from python_hunter.domain.operations.incidents import IncidentCorrelationEngine, SecurityIncident
from python_hunter.domain.operations.scheduler import SecurityScheduler, MonitoredRepository
from python_hunter.domain.operations.health import SecurityPlatformHealth, HealthState
from python_hunter.infrastructure.operations.webhooks import GitHubWebhookValidator, AuditLogger

# Step 42: Enterprise Multi-Tenancy & Governance
from python_hunter.domain.governance.tenant import Organization, OrganizationStatus, Environment, AssetCriticality, Project, TenantContext
from python_hunter.domain.governance.auth import User, UserStatus, Session, ApiToken
from python_hunter.domain.governance.rbac import RBACEngine, SystemRole, Team, TeamMembership, OrganizationMembership
from python_hunter.domain.governance.engine import GovernanceEngine, SecurityApproval, RiskAcceptance
from python_hunter.domain.governance.compliance import ComplianceEngine, SecurityControl, ComplianceEvidence

# Step 43: Enterprise Integrations & Security Ecosystem
from python_hunter.domain.integrations.models import Integration, IntegrationProviderType, IntegrationStatus, ExternalReference, IntegrationEvent
from python_hunter.domain.integrations.credentials import CredentialManager
from python_hunter.domain.integrations.engine import IntegrationEngine, IntegrationRegistry, IntegrationCircuitBreaker, IntegrationSyncEngine

# Step 44: Distributed Architecture, Scalability & Production Hardening
from python_hunter.infrastructure.scaling.quotas import QuotaManager, ResourceQuota
from python_hunter.infrastructure.scaling.distributed_queue import PriorityJobQueue, DeadLetterQueue, JobState, JobPriority, PriorityJob
from python_hunter.infrastructure.scaling.locks import LockManager
from python_hunter.infrastructure.scaling.bulkhead import BulkheadManager, WorkerPoolType
from python_hunter.infrastructure.scaling.sandboxing import ScannerSandbox, SandboxConfig
from python_hunter.infrastructure.storage.cache import CacheAbstraction
from python_hunter.infrastructure.storage.object_storage import LocalObjectStorage
from python_hunter.infrastructure.storage.search import ScalableSearchEngine
from python_hunter.infrastructure.telemetry.logging import StructuredLogger
from python_hunter.infrastructure.telemetry.metrics import MetricsCollector
from python_hunter.infrastructure.telemetry.tracing import TraceContext
from python_hunter.infrastructure.telemetry.health import DependencyHealthStatus, HealthState as DepHealthState
from python_hunter.infrastructure.governance.feature_flags import FeatureFlagService
from python_hunter.infrastructure.governance.configuration import ConfigurationManager
from python_hunter.domain.language.analyzer import AnalyzerRegistry


class SecurityApplicationService:
    """Unified application service wrapping scanning, policy evaluation, multi-language engine, intelligence platform, continuous operations, enterprise governance, enterprise integrations, and distributed production hardening."""

    def __init__(self) -> None:
        self.orchestrator = ScanOrchestrator()
        self.policy_engine = PolicyEngine()
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
        # Seed initial intelligence lazily
        # self.intel_db.save_records(self.intel_engine.ingest_intelligence())

        self.event_bus = SecurityEventBus()
        self.job_queue = SecurityJobQueue()
        self.worker = None
        self.impact_engine = ChangeImpactEngine()
        self.drift_engine = SecurityDriftEngine()
        self.alert_engine = AlertEngine()
        self.notification_registry = NotificationRegistry()
        self.notification_registry.register(MockSlackNotificationProvider())
        self.incident_engine = IncidentCorrelationEngine()
        self.scheduler = None
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
                password_hash="$2b$12$eImiTXuWVxfM37uY4JANjO5E/S8f5n45o1.zW5p5w6V5x5y5z5a5b",
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
        self.cache_abstraction = CacheAbstraction()
        self.object_storage = LocalObjectStorage()
        self.search_engine = ScalableSearchEngine()
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
        findings = self.list_findings()
        finding = next((f for f in findings if f["id"] == finding_id), None)
        if not finding:
            finding = {
                "id": finding_id,
                "rule_id": "PYH-AST-001",
                "title": "SQL Injection in User Endpoint",
                "file_path": "src/api/users.py",
                "confidence": "HIGH",
                "reachability": "REACHABLE",
                "source": "request.args.get('id')",
                "sink": "cursor.execute()",
            }

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
        sast = self.list_findings()
        deps = self.list_dependencies()
        infra_res = [
            {"id": "c1", "name": "app-container", "type": "DOCKERFILE", "is_privileged": True},
            {"id": "db1", "name": "user-db", "type": "CLOUD_DATABASE", "is_publicly_exposed": False},
        ]
        graph, paths, clusters = self.graph_engine.synthesize_cross_domain_graph(
            sast_findings=sast,
            sca_findings=deps,
            infrastructure_resources=infra_res,
        )
        return WhatIfAnalyzer.simulate_remediation(graph, self.graph_engine.attack_path_engine, remediated_finding_ids)

    def get_system_info(self) -> dict[str, Any]:
        return {
            "name": "Python Hunter Security Platform",
            "version": "1.0.0",
            "supported_languages": [m.display_name for m in self.language_registry.list_metadata()],
            "supported_frameworks": [f.name for f in self.framework_registry.list_frameworks()],
            "status": "OPERATIONAL",
        }

    def get_dashboard_summary(self) -> dict[str, Any]:
        return {
            "security_score": 84,
            "previous_score": 78,
            "score_delta": 6,
            "risk_level": "MEDIUM",
            "gate_status": "PASS",
            "counts_by_severity": {
                "CRITICAL": 2,
                "HIGH": 5,
                "MEDIUM": 12,
                "LOW": 18,
                "INFO": 4,
            },
            "new_regressions_count": 1,
            "total_findings": 41,
            "total_repositories": 4,
            "total_scans": 28,
            "failed_policies_count": 0,
            "warnings_count": 2,
            "exceptions_count": 1,
        }

    def list_repositories() -> list[dict[str, Any]]:
        return [
            {
                "id": "repo-1",
                "name": "Python hunter (Local Workspace)",
                "provider": "local",
                "url_or_path": "/run/media/kayi/New Volume/Python hunter",
                "default_branch": "main",
                "last_scan_at": datetime.now(timezone.utc).isoformat(),
                "security_score": 84,
                "risk_level": "MEDIUM",
                "open_findings_count": 7,
                "status": "HEALTHY",
            },
            {
                "id": "repo-2",
                "name": "kayinamura-karimba-geofrey/python-hunter",
                "provider": "github",
                "url_or_path": "https://github.com/kayinamura-karimba-geofrey/python-hunter",
                "default_branch": "main",
                "last_scan_at": datetime.now(timezone.utc).isoformat(),
                "security_score": 88,
                "risk_level": "LOW",
                "open_findings_count": 3,
                "status": "HEALTHY",
            },
        ]

    def list_findings(
        self,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        sample_findings = [
            {
                "id": "find-101",
                "title": "SQL Injection in User Lookup Query",
                "rule_id": "PYH-SQLI-001",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "risk_score": 9.2,
                "exploitability_score": 8.5,
                "language": "Python",
                "framework": "FastAPI",
                "file_path": "src/python_hunter/domain/db.py",
                "line_number": 42,
                "function_name": "get_user_by_id",
                "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "description": "User input directly formatted into SQL statement string leading to remote code execution or data leakage.",
                "remediation_guidance": "Use parameterized queries or SQLAlchemy ORM query binding instead of string concatenation.",
                "why_it_matters": "SQL injection allows unauthorized attackers to dump, alter, or drop entire database tables.",
                "status": "OPEN",
                "service_name": "Auth Service",
                "endpoint": "/api/v1/users/{id}",
            },
            {
                "id": "find-102",
                "title": "Hardcoded High-Entropy Secret Key",
                "rule_id": "PYH-SECRET-002",
                "severity": "HIGH",
                "confidence": "HIGH",
                "risk_score": 8.0,
                "exploitability_score": 7.2,
                "language": "Python",
                "framework": "Django",
                "file_path": "config/settings.py",
                "line_number": 15,
                "function_name": None,
                "code_snippet": "SECRET_KEY = 'django-insecure-89f#@#@$d98s7f9d8f79s8d'",
                "description": "Hardcoded API or secret key detected in source code control.",
                "remediation_guidance": "Extract secret to environment variables or secret manager (e.g. AWS Secrets Manager).",
                "why_it_matters": "Leaked secret keys compromise cryptographic signatures and token security.",
                "status": "OPEN",
                "service_name": "Core Platform",
                "endpoint": None,
            },
            {
                "id": "find-103",
                "title": "Cross-Site Scripting (XSS) via Unsanitized Template Output",
                "rule_id": "PYH-XSS-005",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "risk_score": 5.8,
                "exploitability_score": 6.1,
                "language": "JavaScript",
                "framework": "Express",
                "file_path": "views/render.js",
                "line_number": 88,
                "function_name": "renderUserProfile",
                "code_snippet": "element.innerHTML = req.query.bio;",
                "description": "User query parameter rendered directly as innerHTML without HTML escaping.",
                "remediation_guidance": "Use textContent or DOMPurify.sanitize before injecting HTML string into DOM.",
                "why_it_matters": "XSS allows session hijacking and malicious script execution in user browsers.",
                "status": "NEW",
                "service_name": "Frontend Web Service",
                "endpoint": "/profile",
            },
        ]

        results = sample_findings
        if severity:
            results = [f for f in results if f["severity"].upper() == severity.upper()]
        if status:
            results = [f for f in results if f["status"].upper() == status.upper()]
        if search:
            s = search.lower()
            results = [
                f for f in results
                if s in f["title"].lower() or s in f["rule_id"].lower() or s in f["file_path"].lower()
            ]
        return results

    def list_attack_paths(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "ap-01",
                "title": "Unauthenticated API to DB Remote Code Execution",
                "entry_point": "/api/v1/users/{id}",
                "target_asset": "User Database Cluster",
                "affected_services": ["Auth Service", "Core DB"],
                "risk_score": 9.4,
                "exploitability_score": 8.8,
                "confidence": "HIGH",
                "remediation": "Apply JWT authentication middleware and parameterize SQL queries in get_user_by_id.",
                "nodes": [
                    {"id": "n1", "label": "Internet / Public Client", "type": "internet", "risk_score": 0.0},
                    {"id": "n2", "label": "Unauthenticated GET /api/v1/users/{id}", "type": "api", "risk_score": 7.5},
                    {"id": "n3", "label": "Auth Service (FastAPI)", "type": "service", "risk_score": 8.2},
                    {"id": "n4", "label": "PostgreSQL User Database", "type": "database", "risk_score": 9.4},
                ],
                "edges": [
                    {"source": "n1", "target": "n2", "label": "Public HTTP GET Request", "type": "request"},
                    {"source": "n2", "target": "n3", "label": "Route Dispatch", "type": "dataflow"},
                    {"source": "n3", "target": "n4", "label": "Unsafe SQL Execution", "type": "trust"},
                ],
            }
        ]

    def list_dependencies(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "dep-1",
                "package_name": "urllib3",
                "current_version": "1.26.4",
                "ecosystem": "PyPI",
                "is_direct": True,
                "is_production": True,
                "vulnerability_status": "VULNERABLE",
                "vulnerable_versions": "< 1.26.5",
                "advisory_id": "GHSA-r64q-w8jr-g9qp",
                "severity": "HIGH",
                "fixed_in_version": "1.26.5",
                "risk_score": 7.5,
            },
            {
                "id": "dep-2",
                "package_name": "fastapi",
                "current_version": "0.104.1",
                "ecosystem": "PyPI",
                "is_direct": True,
                "is_production": True,
                "vulnerability_status": "SAFE",
                "vulnerable_versions": None,
                "advisory_id": None,
                "severity": None,
                "fixed_in_version": None,
                "risk_score": 1.2,
            },
        ]

    def list_services() -> list[dict[str, Any]]:
        return [
            {
                "id": "srv-1",
                "name": "Auth Service",
                "language": "Python",
                "framework": "FastAPI",
                "exposure": "public",
                "api_count": 8,
                "dependency_count": 14,
                "risk_score": 8.5,
            },
            {
                "id": "srv-2",
                "name": "Core Intelligence Platform",
                "language": "Python",
                "framework": "Django",
                "exposure": "internal",
                "api_count": 22,
                "dependency_count": 35,
                "risk_score": 4.1,
            },
        ]

    def list_apis() -> list[dict[str, Any]]:
        return [
            {
                "id": "api-1",
                "method": "POST",
                "path": "/api/v1/scans",
                "service_name": "Auth Service",
                "is_authenticated": True,
                "is_authorized": True,
                "has_auth_missing": False,
                "is_sensitive": True,
                "risk_score": 2.1,
            },
            {
                "id": "api-2",
                "method": "GET",
                "path": "/api/v1/users/{id}",
                "service_name": "Auth Service",
                "is_authenticated": False,
                "is_authorized": False,
                "has_auth_missing": True,
                "is_sensitive": True,
                "risk_score": 9.2,
            },
        ]

    def list_history() -> list[dict[str, Any]]:
        return [
            {
                "timestamp": "2026-08-15T10:00:00Z",
                "commit": "a1b2c3d",
                "score": 72,
                "critical_count": 4,
                "high_count": 8,
                "medium_count": 15,
                "low_count": 20,
                "new_findings": 5,
                "fixed_findings": 2,
                "regressions": 2,
            },
            {
                "timestamp": "2026-08-18T14:30:00Z",
                "commit": "e5f6g7h",
                "score": 78,
                "critical_count": 3,
                "high_count": 6,
                "medium_count": 14,
                "low_count": 19,
                "new_findings": 1,
                "fixed_findings": 4,
                "regressions": 1,
            },
            {
                "timestamp": "2026-08-20T09:00:00Z",
                "commit": "j9k8l7m",
                "score": 84,
                "critical_count": 2,
                "high_count": 5,
                "medium_count": 12,
                "low_count": 18,
                "new_findings": 0,
                "fixed_findings": 3,
                "regressions": 0,
            },
        ]

    def list_regressions() -> list[dict[str, Any]]:
        return [
            {
                "id": "reg-1",
                "regression_type": "NEW_CRITICAL_VULNERABILITY",
                "severity": "CRITICAL",
                "commit": "a1b2c3d",
                "status": "OPEN",
                "risk_impact": "SECURITY_SCORE_DECREASED",
                "previous_state": "PASS",
                "current_state": "FAIL",
                "introducing_commit": "a1b2c3d",
                "fixing_commit": None,
                "affected_files": ["src/python_hunter/domain/db.py"],
                "affected_endpoint": "/api/v1/users/{id}",
            }
        ]

    def list_policies() -> list[dict[str, Any]]:
        return [
            {
                "id": "pol-1",
                "name": "Zero Critical Vulnerabilities Policy",
                "description": "Blocks CI/CD builds if any critical severity finding is detected.",
                "status": "WARN",
                "conditions": ["critical_findings == 0"],
                "affected_findings_count": 2,
                "exceptions_count": 1,
            },
            {
                "id": "pol-2",
                "name": "Minimum Security Score Standard",
                "description": "Requires minimum overall platform security score of 80.",
                "status": "PASS",
                "conditions": ["security_score >= 80"],
                "affected_findings_count": 0,
                "exceptions_count": 0,
            },
        ]

    def list_compliance() -> list[dict[str, Any]]:
        return [
            {
                "id": "comp-1",
                "framework": "OWASP Top 10 2021",
                "control_id": "A01:2021-Broken Access Control",
                "title": "Enforce Least Privilege and Endpoint Authorization",
                "status": "FAIL",
                "evidence_count": 2,
                "affected_findings_count": 2,
                "remediation_summary": "Implement authorization middleware on missing GET /api/v1/users/{id}.",
            },
            {
                "id": "comp-2",
                "framework": "OWASP Top 10 2021",
                "control_id": "A03:2021-Injection",
                "title": "Sanitize and Parameterize All Data Queries",
                "status": "FAIL",
                "evidence_count": 1,
                "affected_findings_count": 1,
                "remediation_summary": "Replace string formatting SQL in src/python_hunter/domain/db.py with bind parameters.",
            },
            {
                "id": "comp-3",
                "framework": "PCI-DSS v4.0",
                "control_id": "6.2.4",
                "title": "Software Vulnerability Prevention",
                "status": "PASS",
                "evidence_count": 12,
                "affected_findings_count": 0,
                "remediation_summary": "All high severity injection vectors sealed.",
            },
        ]

    def list_reports() -> list[dict[str, Any]]:
        return [
            {
                "id": "rep-101",
                "report_type": "SARIF",
                "scan_id": "scan-8821",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "READY",
                "download_url": "/api/v1/reports/rep-101/download",
            },
            {
                "id": "rep-102",
                "report_type": "JSON",
                "scan_id": "scan-8821",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "READY",
                "download_url": "/api/v1/reports/rep-102/download",
            },
        ]

    def list_audit_logs() -> list[dict[str, Any]]:
        return [
            {
                "id": "aud-1",
                "event": "SCAN_EXECUTED",
                "actor": "admin@pythonhunter.io",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "resource": "Local Workspace",
                "result": "SUCCESS",
            },
            {
                "id": "aud-2",
                "event": "POLICY_EXCEPTION_GRANTED",
                "actor": "secops@pythonhunter.io",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "resource": "PYH-SQLI-001",
                "result": "SUCCESS",
            },
        ]

    def execute_scan(self, target_path: str, profile: str = "strict") -> dict[str, Any]:
        scan_result = self.orchestrator.run_scan(target_path)
        findings = scan_result.findings
        risk_score = scan_result.risk_summary.get("total_risk_score", 0.0) if hasattr(scan_result, "risk_summary") else 0.0
        gate_result = self.policy_engine.evaluate_gate(findings, risk_score=risk_score, profile=profile)

        return {
            "target": target_path,
            "findings_count": len(findings),
            "risk_score": risk_score,
            "gate_status": gate_result.status.value,
            "violations": gate_result.violations,
            "exit_code": gate_result.exit_code,
        }

    def list_github_installations(self) -> list[dict[str, Any]]:
        return [
            {
                "installation_id": "inst-9941",
                "organization": "kayinamura-karimba-geofrey",
                "repositories": ["kayinamura-karimba-geofrey/python-hunter", "kayinamura-karimba-geofrey/vaultpay"],
                "permissions": ["repository_metadata", "contents", "pull_requests", "checks", "issues_comments"],
                "status": "ACTIVE",
                "installed_at": "2026-08-01T12:00:00Z",
            }
        ]

    def get_webhook_status(self) -> dict[str, Any]:
        return self.webhook_queue.get_status_summary()

    def process_github_webhook(
        self, raw_body: bytes, signature_header: str | None, delivery_id: str | None, event_type: str
    ) -> dict[str, Any]:
        parse_res = self.webhook_handler.parse_event(raw_body, signature_header, delivery_id, event_type)
        if parse_res.get("status") == "ACCEPTED":
            job = self.webhook_queue.enqueue_event(
                delivery_id=delivery_id or "deliv-anon",
                event_type=event_type,
                payload=parse_res["payload"],
            )
            # Process job
            self.webhook_queue.process_next(lambda j: self._handle_queued_webhook_job(j))
            return {
                "status": "ACCEPTED",
                "job_id": job.job_id,
                "message": f"Webhook {event_type} event enqueued successfully.",
            }
        return parse_res

    def _handle_queued_webhook_job(self, job) -> None:
        if job.event_type == "pull_request":
            pr_data = job.payload.get("pull_request", {})
            repo = job.payload.get("repository", {}).get("full_name", "kayinamura-karimba-geofrey/python-hunter")
            pr_num = pr_data.get("number", 42)
            base_sha = pr_data.get("base", {}).get("sha", "a1b2c3d4e5")
            head_sha = pr_data.get("head", {}).get("sha", "f6g7h8i9j0")
            self.run_pull_request_analysis(repo, pr_num, base_sha, head_sha)

    def list_pull_requests(self) -> list[dict[str, Any]]:
        return [
            {
                "pr_id": "pr-42",
                "pr_number": 42,
                "repository": "kayinamura-karimba-geofrey/python-hunter",
                "title": "Add JWT auth and SQL injection fix",
                "author": "kayinamura-geofrey",
                "base_branch": "main",
                "head_branch": "feature/auth-hardening",
                "head_sha": "f6g7h8i9j0",
                "status": "OPEN",
                "security_score": 84,
                "score_delta": +6,
                "risk_level": "LOW",
                "policy_result": "PASS",
                "new_vulnerabilities_count": 0,
                "fixed_vulnerabilities_count": 3,
                "new_attack_paths_count": 0,
                "dependency_regressions_count": 0,
                "secrets_found_count": 0,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        ]

    def get_pull_request_detail(self, pr_id: str) -> dict[str, Any]:
        prs = self.list_pull_requests()
        for p in prs:
            if p["pr_id"] == pr_id or str(p["pr_number"]) == pr_id:
                # Add full detail payload
                detail = dict(p)
                detail.update({
                    "changed_files": [
                        "src/python_hunter/domain/db.py",
                        "src/python_hunter/domain/auth.py",
                        "requirements.txt",
                    ],
                    "security_relevant_files": [
                        "src/python_hunter/domain/db.py",
                        "src/python_hunter/domain/auth.py",
                    ],
                    "new_findings": [],
                    "fixed_findings": [
                        {
                            "id": "find-101",
                            "title": "SQL Injection in User Lookup Query",
                            "severity": "CRITICAL",
                            "rule_id": "PYH-SQLI-001",
                            "file_path": "src/python_hunter/domain/db.py",
                            "line_number": 42,
                        }
                    ],
                    "new_attack_paths": [],
                    "fixed_attack_paths": [],
                    "dependency_regressions": [],
                    "secret_regressions": [],
                    "timeline": [
                        {"event": "WEBHOOK_RECEIVED", "timestamp": "2026-08-20T21:00:00Z", "details": "PR #42 synchronize event received."},
                        {"event": "SCAN_STARTED", "timestamp": "2026-08-20T21:00:02Z", "details": "Base & Head snapshots analyzed."},
                        {"event": "REGRESSION_CHECKED", "timestamp": "2026-08-20T21:00:05Z", "details": "3 vulnerabilities fixed, score improved by +6."},
                        {"event": "POLICY_EVALUATED", "timestamp": "2026-08-20T21:00:06Z", "details": "Policy Engine status: PASS."},
                        {"event": "CHECK_RUN_UPDATED", "timestamp": "2026-08-20T21:00:07Z", "details": "GitHub Check Run updated to success."},
                    ]
                })
                return detail
        return prs[0]

    def run_pull_request_analysis(
        self,
        repository: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        base_findings: list[dict[str, Any]] | None = None,
        head_findings: list[dict[str, Any]] | None = None,
        changed_files: list[str] | None = None,
    ) -> dict[str, Any]:
        base_f = base_findings if base_findings is not None else [
            {
                "id": "find-101",
                "title": "SQL Injection in User Lookup Query",
                "rule_id": "PYH-SQLI-001",
                "severity": "CRITICAL",
                "risk_score": 9.2,
                "file_path": "src/python_hunter/domain/db.py",
                "line_number": 42,
            }
        ]
        head_f = head_findings if head_findings is not None else []
        c_files = changed_files if changed_files is not None else ["src/python_hunter/domain/db.py"]

        res = self.pr_engine.analyze_pull_request(
            pr_number=pr_number,
            repository=repository,
            base_sha=base_sha,
            head_sha=head_sha,
            base_findings=base_f,
            head_findings=head_f,
            base_attack_paths=[],
            head_attack_paths=[],
            changed_files=c_files,
            base_dependencies=[],
            head_dependencies=[],
        )

        summary = self.pr_engine.generate_summary(res, {"id": f"pr-{pr_number}", "number": pr_number, "repository": repository})
        check_run = self.checks_service.build_check_run(res, summary)
        pr_comment = self.comment_service.post_or_update_pr_comment(repository, pr_number, summary.summary_markdown)

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
        import os
        from python_hunter.domain.ir.models import IRLocation
        from python_hunter.domain.semantics.program_model import ProgramModel, ProgramModule, ProgramFunction, ProgramCall
        from python_hunter.domain.semantics.symbol_table import SymbolTable, NameResolver
        from python_hunter.domain.semantics.call_graph_2 import CallGraph2
        from python_hunter.domain.semantics.taint_registries import TaintSourceRegistry, TaintSinkRegistry, SanitizerRegistry
        from python_hunter.domain.semantics.interprocedural_engine import InterproceduralEngine
        from python_hunter.domain.semantics.rule_engine_2 import RuleEngine2
        from python_hunter.domain.semantics.cache_engine import AnalysisCacheEngine, AnalysisLimits

        opts = options or {}
        max_depth = opts.get("max_call_depth", 10)
        limits = AnalysisLimits(max_call_depth=max_depth)
        cache = AnalysisCacheEngine(limits)

        # 1. Build ProgramModel from workspace
        model = ProgramModel()
        symbol_table = SymbolTable()

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb")):
                    full_path = os.path.join(root, file)
                    mod_name = os.path.splitext(file)[0]
                    mod = ProgramModule(name=mod_name, file_path=full_path, language=Language.PYTHON)

                    # Simple synthetic function extraction for interprocedural demonstration
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    current_fn = None
                    for idx, line in enumerate(lines, 1):
                        line_str = line.strip()
                        if "def " in line_str or "function " in line_str or "func " in line_str or "void " in line_str:
                            func_name = line_str.split("(")[0].replace("def ", "").replace("function ", "").replace("func ", "").replace("void ", "").strip()
                            qual_name = f"{mod_name}.{func_name}"
                            current_fn = ProgramFunction(
                                name=func_name,
                                qualified_name=qual_name,
                                module_name=mod_name,
                                is_endpoint_handler=("route" in func_name.lower() or "get" in func_name.lower() or "controller" in line_str.lower()),
                                location=IRLocation(file_path=full_path, start_line=idx),
                            )
                            mod.functions[qual_name] = current_fn
                        elif current_fn and "(" in line_str:
                            callee = line_str.split("(")[0].strip().split()[-1]
                            if callee and callee not in ("def", "if", "for", "while", "return"):
                                current_fn.calls.append(ProgramCall(
                                    caller_qualified_name=current_fn.qualified_name,
                                    callee_name=callee,
                                    location=IRLocation(file_path=full_path, start_line=idx),
                                ))

                    model.add_module(mod)

        # 2. Build CallGraph2 & InterproceduralEngine
        name_resolver = NameResolver(model, symbol_table)
        call_graph = CallGraph2(model, name_resolver)
        call_graph.build()

        sources = TaintSourceRegistry()
        sinks = TaintSinkRegistry()
        sanitizers = SanitizerRegistry()

        engine = InterproceduralEngine(model, call_graph, sources, sinks, sanitizers)
        evidences = engine.analyze_workspace()

        rule_engine = RuleEngine2(model, call_graph)
        findings = rule_engine.evaluate_composite_findings(evidences)

        return {
            "status": "COMPLETED",
            "workspace_path": workspace_path,
            "total_nodes": len(call_graph.nodes),
            "total_modules": len(model.modules),
            "total_functions": len(model.all_functions()),
            "total_call_edges": len(call_graph.edges),
            "total_evidences": len(evidences),
            "evidence_count": len(evidences),
            "findings_count": len(findings),
            "findings": findings,
            "cache_stats": cache.get_stats(),
        }

    def execute_sca_scan(self, workspace_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Performs Software Composition Analysis (SCA), Dependency Graphing, Reachability, and License Policy checks."""
        import os
        from python_hunter.domain.dependencies.lockfile_parsers import UniversalLockfileParser
        from python_hunter.domain.dependencies.models import DependencyGraph, DependencyInventory
        from python_hunter.domain.dependencies.dependency_graph_engine import DependencyGraphEngine
        from python_hunter.domain.dependencies.advisory_db import AdvisoryDatabase
        from python_hunter.domain.dependencies.vulnerability_intel import VulnerabilityIntelligence
        from python_hunter.domain.dependencies.reachability_engine import ReachabilityEngine
        from python_hunter.domain.dependencies.license_policy import LicensePolicyEngine
        from python_hunter.domain.dependencies.remediation_engine import RemediationEngine

        db = AdvisoryDatabase()
        intel = VulnerabilityIntelligence([db])
        lic_engine = LicensePolicyEngine()

        # Build ProgramModel for function-level reachability analysis
        from python_hunter.domain.ir.models import IRLocation
        from python_hunter.domain.semantics.program_model import ProgramModel, ProgramModule, ProgramFunction, ProgramCall
        from python_hunter.domain.language.models import Language

        model = ProgramModel()
        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb")):
                    full_path = os.path.join(root, file)
                    mod_name = os.path.splitext(file)[0]
                    mod = ProgramModule(name=mod_name, file_path=full_path, language=Language.PYTHON)

                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    current_fn = None
                    for idx, line in enumerate(lines, 1):
                        line_str = line.strip()
                        if "def " in line_str or "function " in line_str or "func " in line_str:
                            func_name = line_str.split("(")[0].replace("def ", "").replace("function ", "").replace("func ", "").strip()
                            qual_name = f"{mod_name}.{func_name}"
                            current_fn = ProgramFunction(
                                name=func_name,
                                qualified_name=qual_name,
                                module_name=mod_name,
                                is_endpoint_handler=("route" in func_name.lower() or "get" in func_name.lower() or "handler" in line_str.lower() or "request" in line_str.lower()),
                                location=IRLocation(file_path=full_path, start_line=idx),
                            )
                            mod.functions[qual_name] = current_fn
                        elif current_fn and "(" in line_str:
                            callee = line_str.split("(")[0].strip().split()[-1]
                            if callee and callee not in ("def", "if", "for", "while", "return"):
                                current_fn.calls.append(ProgramCall(
                                    caller_qualified_name=current_fn.qualified_name,
                                    callee_name=callee,
                                    location=IRLocation(file_path=full_path, start_line=idx),
                                ))

                    model.add_module(mod)

        reach_engine = ReachabilityEngine(model)

        all_deps = []
        manifests = []
        graph = DependencyGraph()

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file in ("requirements.txt", "package.json", "package-lock.json", "poetry.lock", "Pipfile.lock", "pom.xml", "build.gradle", "go.mod", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock"):
                    full_p = os.path.join(root, file)
                    manifests.append(full_p)
                    parsed = UniversalLockfileParser.parse_file(full_p)
                    all_deps.extend(parsed)
                    for dep in parsed:
                        graph.add_dependency(dep)

        analytics = DependencyGraphEngine.analyze_graph(graph)
        vuln_findings = []

        for dep in all_deps:
            advs = intel.match_advisories(dep.name, dep.version or "0.0.0", dep.ecosystem)
            for adv in advs:
                reach = reach_engine.evaluate_reachability(dep, adv, graph)
                remed = RemediationEngine.generate_recommendation(dep, adv)
                lic_eval = lic_engine.evaluate_dependency(dep)

                paths = graph.get_paths_to(dep.name)
                dep_path = " -> ".join(paths[0]) if paths else dep.name

                vuln_findings.append({
                    "package": dep.name,
                    "version": dep.version or "unpinned",
                    "ecosystem": dep.ecosystem.value,
                    "advisory": adv.identifier,
                    "cve": adv.cve_id,
                    "severity": adv.severity,
                    "cvss": adv.cvss,
                    "affected_versions": adv.affected_versions,
                    "patched_version": adv.patched_versions,
                    "dependency_path": dep_path,
                    "is_direct": dep.is_direct,
                    "reachability": {
                        "is_reachable": reach.is_reachable,
                        "confidence": reach.confidence.value,
                        "evidence": reach.evidence_summary,
                        "call_trace": reach.call_trace,
                    },
                    "license": {
                        "name": lic_eval.license,
                        "policy_action": lic_eval.action.value,
                        "reason": lic_eval.reason,
                    },
                    "remediation": {
                        "action": remed.action,
                        "recommended_version": remed.recommended_version,
                        "breaking_risk": remed.breaking_change_risk,
                        "reason": remed.reason,
                        "guidance": remed.mitigation_guidance,
                    },
                })

        freshness = db.get_freshness_info()

        return {
            "status": "COMPLETED",
            "workspace_path": workspace_path,
            "manifests": manifests,
            "dependency_inventory": {
                "total_dependencies": analytics.total_nodes,
                "direct_count": analytics.direct_count,
                "transitive_count": analytics.transitive_count,
                "max_depth": analytics.max_depth,
                "average_depth": analytics.average_depth,
                "bloat_factor": analytics.bloat_factor,
                "single_points_of_failure": analytics.single_points_of_failure,
            },
            "vulnerability_findings_count": len(vuln_findings),
            "vulnerability_findings": vuln_findings,
            "database_metadata": {
                "version": freshness.database_version,
                "last_update": freshness.last_update,
                "source": freshness.source,
                "total_advisories": freshness.total_advisories,
                "is_stale": freshness.is_stale,
            },
            "dependency_tree": graph.to_tree_str(),
        }

    def execute_secrets_scan(
        self, workspace_path: str, scan_history: bool = False, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Scans workspace source code, configuration files, and optionally Git history for credential leaks."""
        import os
        from python_hunter.domain.analysis.context import AnalysisContext
        from python_hunter.domain.secrets.engine import SecretDetectionEngine
        from python_hunter.domain.secrets.git_history_engine import GitHistorySecretScanner
        from python_hunter.domain.secrets.attack_path_secrets import AttackPathSecretMapper

        from python_hunter.domain.projects.project import Project
        sec_engine = SecretDetectionEngine()
        context = AnalysisContext(scan_id="scan_sec", project=Project(name="workspace", root_path=workspace_path))
        all_findings = []

        # 1. Active workspace scanning
        for root, _, files in os.walk(workspace_path):
            if ".git" in root:
                continue
            for file in files:
                full_p = os.path.join(root, file)
                if sec_engine.is_eligible_file(full_p):
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        file_findings = sec_engine.scan_file(full_p, content, context)
                        all_findings.extend(file_findings)
                    except Exception:
                        continue

        # 2. Historical Git commit scanning
        historical_findings = []
        if scan_history:
            git_scanner = GitHistorySecretScanner(sec_engine)
            historical_findings = git_scanner.scan_git_history(workspace_path)

        # 3. Attack path generation
        attack_paths = AttackPathSecretMapper.generate_attack_paths(all_findings)

        formatted_findings = []
        for f in all_findings:
            formatted_findings.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "file_path": f.file_path,
                "line": f.location.line_start,
                "fingerprint": f.fingerprint,
                "evidence": f.evidence,
                "remediation": f.remediation,
            })

        return {
            "status": "COMPLETED",
            "workspace_path": workspace_path,
            "active_secrets_count": len(formatted_findings),
            "active_secrets": formatted_findings,
            "historical_secrets_count": len(historical_findings),
            "historical_secrets": [
                {
                    "fingerprint": h.fingerprint,
                    "secret_type": h.secret_type,
                    "detector_id": h.detector_id,
                    "first_seen_commit": h.first_seen_commit,
                    "first_seen_author": h.first_seen_author,
                    "first_seen_date": h.first_seen_date,
                    "file_path": h.file_path,
                    "current_status": h.current_status,
                }
                for h in historical_findings
            ],
            "attack_paths": [
                {
                    "path_id": ap.path_id,
                    "title": ap.title,
                    "severity": ap.severity,
                    "steps": ap.steps,
                }
                for ap in attack_paths
            ],
        }

    def execute_infrastructure_scan(self, workspace_path: str) -> dict[str, Any]:
        """Scans workspace for Docker, Kubernetes, Helm, Terraform, Cloud, and CI/CD security vulnerabilities."""
        import os
        from python_hunter.domain.infrastructure.models import InfrastructureIR
        from python_hunter.infrastructure.iac.registry import InfrastructureRegistry
        from python_hunter.infrastructure.iac.docker_adapter import DockerAdapter
        from python_hunter.infrastructure.iac.k8s_adapter import KubernetesAdapter
        from python_hunter.infrastructure.iac.terraform_adapter import TerraformAdapter
        from python_hunter.infrastructure.iac.cicd_adapter import CICDAdapter
        from python_hunter.domain.infrastructure.rules_engine import InfrastructureSecurityRuleEngine
        from python_hunter.domain.infrastructure.graph_engine import CrossLayerGraphEngine

        registry = InfrastructureRegistry()
        registry.register_adapter(DockerAdapter())
        registry.register_adapter(KubernetesAdapter())
        registry.register_adapter(TerraformAdapter())
        registry.register_adapter(CICDAdapter())

        ir = InfrastructureIR(scan_path=workspace_path)

        for root, _, files in os.walk(workspace_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, workspace_path)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    registry.process_file(rel_path, content, ir)
                except Exception:
                    pass

        rule_engine = InfrastructureSecurityRuleEngine()
        findings = rule_engine.evaluate_ir(ir)

        graph_engine = CrossLayerGraphEngine()
        cross_graph = graph_engine.build_cross_layer_graph(ir)
        attack_paths = graph_engine.trace_cross_layer_attack_paths(cross_graph)

        formatted_findings = [
            {
                "id": f"iac-find-{idx+1}",
                "rule_id": f.rule_id,
                "title": f.rule_name,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "evidence": f.evidence,
                "description": f.description,
                "remediation": f.remediation,
            }
            for idx, f in enumerate(findings)
        ]

        resources_formatted = [
            {
                "id": r.id,
                "name": r.name,
                "type": r.type.value,
                "provider": r.provider,
                "file_path": r.file_path,
                "line": r.line,
                "is_publicly_exposed": r.is_publicly_exposed,
                "is_privileged": r.is_privileged,
                "runs_as_root": r.runs_as_root,
                "has_encryption_enabled": r.has_encryption_enabled,
            }
            for r in ir.resources
        ]

        return {
            "status": "COMPLETED",
            "workspace_path": workspace_path,
            "resources_count": len(resources_formatted),
            "resources": resources_formatted,
            "findings_count": len(formatted_findings),
            "findings": formatted_findings,
            "attack_paths_count": len(attack_paths),
            "attack_paths": attack_paths,
        }

