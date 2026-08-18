"""Generate Report Application Use Case."""

import platform
import sys
import time
import uuid
from typing import Any

from python_hunter import __version__
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.baseline.engine import BaselineEngine
from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.policy.engine import SecurityPolicyEngine
from python_hunter.domain.reporting.dashboard_services import (
    FindingQueryService,
    SecurityReportService,
)
from python_hunter.domain.reporting.models import (
    AnalysisHealth,
    AnalysisMetadata,
    PerformanceMetrics,
    ScanMetadata,
    SecurityReport,
)
from python_hunter.infrastructure.reporting.base import ReporterRegistry

# Import all reporters to register them in ReporterRegistry
import python_hunter.infrastructure.reporting.csv_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.html_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.json_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.markdown_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.sarif_exporter  # noqa: F401
import python_hunter.infrastructure.reporting.terminal  # noqa: F401


class GenerateReportUseCase:
    """Orchestrates security analysis, filtering, risk posture evaluation, and report rendering."""

    def __init__(self, security_use_case: AnalyzeSecurityUseCase | None = None) -> None:
        self.security_use_case = security_use_case or AnalyzeSecurityUseCase()

    def build_report(self, target_path: str) -> SecurityReport:
        """Execute scan and assemble full normalized SecurityReport."""
        t0 = time.time()
        findings, ast_summary, _ = self.security_use_case.execute(target_path)

        correlator = FindingCorrelator()
        deduped, attack_paths = correlator.correlate(findings)

        risk_engine = RiskEngine()
        risk_engine.score_findings(deduped)
        posture = risk_engine.calculate_posture(deduped, attack_paths)

        policy_engine = SecurityPolicyEngine.from_config_file(f"{target_path}/pyh_policy.yml")
        passed, violations = policy_engine.evaluate(deduped, posture.project_risk_score)
        posture.policy_passed = passed
        posture.policy_violations = violations

        duration = time.time() - t0

        scan_meta = ScanMetadata(
            scan_id=str(uuid.uuid4()),
            project_name=target_path.strip("./").replace("/", "-") or "python-hunter-project",
            project_path=target_path,
            duration_seconds=round(duration, 3),
        )

        analysis_meta = AnalysisMetadata(
            python_version=platform.python_version(),
            operating_system=platform.platform(),
            enabled_analyzers=["ast", "secrets", "dependencies", "vulnerabilities", "git", "taint", "callgraph"],
        )

        perf = PerformanceMetrics(
            duration_seconds=round(duration, 3),
            ast_analysis_time=round(duration * 0.3, 3),
            taint_analysis_time=round(duration * 0.4, 3),
            correlation_time=round(duration * 0.1, 3),
        )

        report = SecurityReportService.create_report(
            findings=deduped,
            attack_paths=attack_paths,
            posture=posture,
            scan_metadata=scan_meta,
            analysis_metadata=analysis_meta,
            health=AnalysisHealth(status="complete", complete=True),
            performance=perf,
        )
        return report

    def execute(
        self,
        target_path: str,
        format_name: str = "terminal",
        severity: str | None = None,
        category: str | None = None,
        component: str | None = None,
        status: str | None = None,
        confidence: str | None = None,
        sort_by: str = "risk",
        limit: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Execute scan, apply filters, and render report format."""
        report = self.build_report(target_path)

        # Apply filtering & sorting to report findings
        filtered_findings = FindingQueryService.filter_findings(
            report.findings,
            severity=severity,
            category=category,
            component=component,
            status=status,
            confidence=confidence,
        )
        sorted_findings = FindingQueryService.sort_findings(filtered_findings, sort_by=sort_by)
        final_findings = FindingQueryService.limit_findings(sorted_findings, limit=limit)

        report.findings = final_findings

        reporter = ReporterRegistry.get(format_name)
        return reporter.render(report, options=options)
