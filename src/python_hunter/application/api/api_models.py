"""API Pydantic Schemas for Python Hunter REST API."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class GateStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: dict[str, Any]


class SystemInfoResponse(BaseModel):
    name: str
    version: str
    supported_languages: list[str]
    supported_frameworks: list[str]
    status: str


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Local path or Git repository URL to scan")
    branch: Optional[str] = ""
    commit: Optional[str] = ""
    profile: str = Field("strict", description="Scan profile (strict, default, production)")
    policy: Optional[str] = "default-security-policy"
    baseline: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: JobStatus
    message: str


class DashboardSummaryResponse(BaseModel):
    security_score: int
    previous_score: int
    score_delta: int
    risk_level: str
    gate_status: GateStatus
    counts_by_severity: dict[str, int]
    new_regressions_count: int
    total_findings: int
    total_repositories: int
    total_scans: int
    failed_policies_count: int
    warnings_count: int
    exceptions_count: int


class FindingModel(BaseModel):
    id: str
    title: str
    rule_id: str
    severity: Severity
    confidence: str
    risk_score: float
    exploitability_score: float
    language: str
    framework: Optional[str] = None
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    code_snippet: str
    description: str
    remediation_guidance: str
    why_it_matters: str
    status: str  # NEW, OPEN, FIXED, REOPENED, SUPPRESSED
    service_name: Optional[str] = None
    endpoint: Optional[str] = None


class RepositoryModel(BaseModel):
    id: str
    name: str
    provider: str  # local or github
    url_or_path: str
    default_branch: str
    last_scan_at: Optional[str] = None
    security_score: int
    risk_level: str
    open_findings_count: int
    status: str


class AttackPathNode(BaseModel):
    id: str
    label: str
    type: str  # internet, api, service, database, asset, external
    risk_score: float


class AttackPathEdge(BaseModel):
    source: str
    target: str
    label: str
    type: str  # request, dataflow, trust


class AttackPathModel(BaseModel):
    id: str
    title: str
    entry_point: str
    target_asset: str
    affected_services: list[str]
    risk_score: float
    exploitability_score: float
    confidence: str
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    remediation: str


class DependencyModel(BaseModel):
    id: str
    package_name: str
    current_version: str
    ecosystem: str
    is_direct: bool
    is_production: bool
    vulnerability_status: str
    vulnerable_versions: Optional[str] = None
    advisory_id: Optional[str] = None
    severity: Optional[Severity] = None
    fixed_in_version: Optional[str] = None
    risk_score: float


class ServiceModel(BaseModel):
    id: str
    name: str
    language: str
    framework: str
    exposure: str  # public, internal, isolated
    api_count: int
    dependency_count: int
    risk_score: float


class ApiEndpointModel(BaseModel):
    id: str
    method: str
    path: str
    service_name: str
    is_authenticated: bool
    is_authorized: bool
    has_auth_missing: bool
    is_sensitive: bool
    risk_score: float


class SecurityHistorySnapshotModel(BaseModel):
    timestamp: str
    commit: str
    score: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    new_findings: int
    fixed_findings: int
    regressions: int


class RegressionModel(BaseModel):
    id: str
    regression_type: str
    severity: Severity
    commit: str
    status: str
    risk_impact: str
    previous_state: str
    current_state: str
    introducing_commit: str
    fixing_commit: Optional[str] = None
    affected_files: list[str]
    affected_endpoint: Optional[str] = None


class PolicyModel(BaseModel):
    id: str
    name: str
    description: str
    status: GateStatus
    conditions: list[str]
    affected_findings_count: int
    exceptions_count: int


class ComplianceControlModel(BaseModel):
    id: str
    framework: str  # OWASP Top 10, PCI-DSS, SOC2
    control_id: str
    title: str
    status: str  # PASS, FAIL, PARTIAL, NOT_ASSESSED
    evidence_count: int
    affected_findings_count: int
    remediation_summary: str


class ReportModel(BaseModel):
    id: str
    report_type: str  # JSON, SARIF, EXECUTIVE_PDF, CSV
    scan_id: str
    created_at: str
    status: str
    download_url: str


class AuditLogModel(BaseModel):
    id: str
    event: str
    actor: str
    timestamp: str
    resource: str
    result: str


class GitHubInstallationModel(BaseModel):
    installation_id: str
    organization: str
    repositories: list[str]
    permissions: list[str]
    status: str
    installed_at: str


class PullRequestSummaryModel(BaseModel):
    pr_id: str
    pr_number: int
    repository: str
    title: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str
    status: str
    security_score: int
    score_delta: int
    risk_level: str
    policy_result: str
    new_vulnerabilities_count: int
    fixed_vulnerabilities_count: int
    new_attack_paths_count: int
    dependency_regressions_count: int
    secrets_found_count: int
    updated_at: Optional[str] = None


class WebhookStatusModel(BaseModel):
    total_events: int
    queued: int
    completed: int
    failed: int
    dead_letter_count: int
    webhook_active: bool

