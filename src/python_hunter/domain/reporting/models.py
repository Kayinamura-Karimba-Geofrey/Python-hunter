"""Domain models for Security Reporting, Metrics, and Dashboard Integration."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from python_hunter import __version__
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.correlation.models import AttackPath, SecurityPosture
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.frameworks.models import APIInventory, FrameworkProfile


@dataclass
class ScanMetadata:
    """Metadata regarding a security scan run."""

    scan_id: str
    project_name: str
    project_path: str
    scanner_version: str = __version__
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: float = 0.0
    configuration_hash: str = "default_hash"
    commit_sha: str | None = None
    branch: str | None = None


@dataclass
class AnalysisMetadata:
    """System runtime and analyzer execution metadata."""

    python_version: str
    operating_system: str
    enabled_analyzers: list[str] = field(default_factory=list)
    disabled_analyzers: list[str] = field(default_factory=list)
    rule_set_version: str = __version__
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityStatistics:
    """Statistical breakdown of scan findings by severity and lifecycle state."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    new_count: int = 0
    existing_count: int = 0
    resolved_count: int = 0
    reopened_count: int = 0
    suppressed_count: int = 0


@dataclass
class RiskMetrics:
    """Project risk evaluation metrics."""

    project_risk_score: float = 0.0
    highest_finding_score: float = 0.0
    average_risk_score: float = 0.0
    max_severity: Severity = Severity.INFO
    critical_attack_paths: int = 0
    high_risk_components: list[str] = field(default_factory=list)


@dataclass
class ComponentMetrics:
    """Component/Module-level security breakdown."""

    name: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_findings: int = 0
    risk_score: float = 0.0


@dataclass
class AnalysisHealth:
    """Health and completion status of execution pipeline analyzers."""

    status: str = "complete"  # complete, partial, failed
    complete: bool = True
    failed_analyzers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PerformanceMetrics:
    """Execution timing and resource metrics."""

    duration_seconds: float = 0.0
    parsing_time: float = 0.0
    ast_analysis_time: float = 0.0
    dependency_analysis_time: float = 0.0
    taint_analysis_time: float = 0.0
    callgraph_analysis_time: float = 0.0
    correlation_time: float = 0.0
    reporting_time: float = 0.0
    analyzer_stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationPriority:
    """Prioritized remediation recommendation item."""

    priority_level: int
    rule_id: str
    title: str
    file_path: str
    line: int
    risk_score: float
    remediation_text: str


@dataclass
class DashboardSnapshot:
    """Dashboard-oriented structured snapshot representation."""

    summary: dict[str, Any]
    severity_distribution: dict[str, int]
    risk_trend: list[dict[str, Any]] = field(default_factory=list)
    finding_trend: list[dict[str, Any]] = field(default_factory=list)
    component_risk: list[dict[str, Any]] = field(default_factory=list)
    top_rules: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    dependency_risk: dict[str, Any] = field(default_factory=dict)
    policy_status: dict[str, Any] = field(default_factory=dict)
    api_summary: dict[str, Any] = field(default_factory=dict)
    dynamic_summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityReport:
    """Unified top-level normalized security report entity."""

    schema_version: str = "1.0"
    scan_metadata: ScanMetadata = field(default_factory=lambda: ScanMetadata(scan_id="0", project_name="", project_path=""))
    analysis_metadata: AnalysisMetadata = field(default_factory=lambda: AnalysisMetadata(python_version="", operating_system=""))
    statistics: SecurityStatistics = field(default_factory=SecurityStatistics)
    risk_metrics: RiskMetrics = field(default_factory=RiskMetrics)
    posture: SecurityPosture = field(default_factory=SecurityPosture)
    health: AnalysisHealth = field(default_factory=AnalysisHealth)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    components: list[ComponentMetrics] = field(default_factory=list)
    remediation_priorities: list[RemediationPriority] = field(default_factory=list)
    framework_profile: FrameworkProfile = field(default_factory=FrameworkProfile)
    api_inventory: APIInventory = field(default_factory=APIInventory)
    dynamic_summary: Any = None
    executive_summary: str = ""
    developer_summary: str = ""
