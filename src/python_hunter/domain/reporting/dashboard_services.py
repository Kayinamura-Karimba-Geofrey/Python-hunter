"""Dashboard Services and Data Contracts for Security Reporting."""

import os
from typing import Any

from python_hunter.domain.common.enums import Category, Confidence, FindingLifecycleState, Severity
from python_hunter.domain.correlation.models import AttackPath, SecurityPosture
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.reporting.models import (
    AnalysisHealth,
    AnalysisMetadata,
    ComponentMetrics,
    DashboardSnapshot,
    PerformanceMetrics,
    RemediationPriority,
    RiskMetrics,
    ScanMetadata,
    SecurityReport,
    SecurityStatistics,
)


class FindingQueryService:
    """Provides filtering, sorting, and pagination capabilities over normalized findings."""

    @staticmethod
    def filter_findings(
        findings: list[Finding],
        severity: Severity | str | None = None,
        category: Category | str | None = None,
        component: str | None = None,
        status: FindingLifecycleState | str | None = None,
        confidence: Confidence | str | None = None,
        file_pattern: str | None = None,
    ) -> list[Finding]:
        """Filter finding collection by multiple optional criteria."""
        res = list(findings)

        if severity:
            sev_val = severity.value if isinstance(severity, Severity) else str(severity).upper()
            res = [f for f in res if f.severity.value == sev_val]

        if category:
            cat_val = category.value if isinstance(category, Category) else str(category).upper()
            res = [f for f in res if f.category.value == cat_val]

        if component:
            comp_lower = component.lower()
            res = [f for f in res if comp_lower in f.file_path.lower()]

        if status:
            stat_val = status.value if isinstance(status, FindingLifecycleState) else str(status).upper()
            res = [f for f in res if f.lifecycle_state.value == stat_val]

        if confidence:
            conf_val = confidence.value if isinstance(confidence, Confidence) else str(confidence).upper()
            res = [f for f in res if f.confidence.value == conf_val]

        if file_pattern:
            fp_lower = file_pattern.lower()
            res = [f for f in res if fp_lower in f.file_path.lower()]

        return res

    @staticmethod
    def sort_findings(findings: list[Finding], sort_by: str = "risk") -> list[Finding]:
        """Sort findings by risk, severity, confidence, or file path."""
        res = list(findings)
        sb = sort_by.lower()

        sev_rank = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
        conf_rank = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}

        if sb in ("risk", "risk_score"):
            res.sort(key=lambda f: f.risk_score, reverse=True)
        elif sb == "severity":
            res.sort(key=lambda f: sev_rank.get(f.severity, 0), reverse=True)
        elif sb == "confidence":
            res.sort(key=lambda f: conf_rank.get(f.confidence, 0), reverse=True)
        elif sb in ("file", "file_path"):
            res.sort(key=lambda f: (f.file_path, f.location.line_start if f.location else 0))

        return res

    @staticmethod
    def limit_findings(findings: list[Finding], limit: int | None = None) -> list[Finding]:
        """Limit maximum number of returned findings."""
        if limit and limit > 0:
            return findings[:limit]
        return findings


class SecurityMetricsService:
    """Calculates statistical, risk, component-level, and remediation metrics."""

    @staticmethod
    def build_statistics(findings: list[Finding]) -> SecurityStatistics:
        """Compute severity and lifecycle counts."""
        stats = SecurityStatistics(total_findings=len(findings))
        for f in findings:
            if f.severity == Severity.CRITICAL:
                stats.critical_count += 1
            elif f.severity == Severity.HIGH:
                stats.high_count += 1
            elif f.severity == Severity.MEDIUM:
                stats.medium_count += 1
            elif f.severity == Severity.LOW:
                stats.low_count += 1
            elif f.severity == Severity.INFO:
                stats.info_count += 1

            if f.lifecycle_state == FindingLifecycleState.NEW:
                stats.new_count += 1
            elif f.lifecycle_state == FindingLifecycleState.EXISTING:
                stats.existing_count += 1
            elif f.lifecycle_state == FindingLifecycleState.RESOLVED:
                stats.resolved_count += 1
            elif f.lifecycle_state == FindingLifecycleState.REOPENED:
                stats.reopened_count += 1
            elif f.lifecycle_state == FindingLifecycleState.SUPPRESSED:
                stats.suppressed_count += 1

        return stats

    @staticmethod
    def build_component_metrics(findings: list[Finding]) -> list[ComponentMetrics]:
        """Group findings by top-level component/directory and compute metrics."""
        comp_map: dict[str, list[Finding]] = {}
        for f in findings:
            parts = [p for p in f.file_path.replace("\\", "/").split("/") if p and p != "."]
            comp = parts[0] if len(parts) > 1 else ("root" if parts else "default")
            comp_map.setdefault(comp, []).append(f)

        components: list[ComponentMetrics] = []
        for name, comp_findings in comp_map.items():
            cm = ComponentMetrics(name=name, total_findings=len(comp_findings))
            scores = []
            for f in comp_findings:
                if f.severity == Severity.CRITICAL:
                    cm.critical_count += 1
                elif f.severity == Severity.HIGH:
                    cm.high_count += 1
                elif f.severity == Severity.MEDIUM:
                    cm.medium_count += 1
                elif f.severity == Severity.LOW:
                    cm.low_count += 1
                scores.append(f.risk_score)

            cm.risk_score = round(max(scores) if scores else 0.0, 1)
            components.append(cm)

        components.sort(key=lambda c: c.risk_score, reverse=True)
        return components

    @staticmethod
    def build_remediation_priorities(findings: list[Finding]) -> list[RemediationPriority]:
        """Rank top findings by risk score to generate prioritized remediations."""
        sorted_findings = FindingQueryService.sort_findings(findings, sort_by="risk")
        priorities: list[RemediationPriority] = []
        for idx, f in enumerate(sorted_findings[:10], 1):
            priorities.append(
                RemediationPriority(
                    priority_level=idx,
                    rule_id=f.rule_id,
                    title=f.title,
                    file_path=f.file_path,
                    line=f.location.line_start if f.location else 0,
                    risk_score=f.risk_score,
                    remediation_text=f.remediation,
                )
            )
        return priorities

    @staticmethod
    def generate_executive_summary(posture: SecurityPosture, stats: SecurityStatistics) -> str:
        """Produce executive summary text."""
        risk_level = "CRITICAL" if posture.project_risk_score >= 80 else ("HIGH" if posture.project_risk_score >= 60 else ("MEDIUM" if posture.project_risk_score >= 30 else "LOW"))
        status_text = "FAILED" if not posture.policy_passed else "PASSED"
        summary = (
            f"The Python Hunter scan identified {stats.total_findings} security findings across the target project. "
            f"Overall project risk level is evaluated as {risk_level} with a score of {posture.project_risk_score}/100. "
            f"The scan detected {stats.critical_count} critical and {stats.high_count} high severity issues. "
            f"Security policy evaluation status is {status_text}."
        )
        return summary

    @staticmethod
    def generate_developer_summary(findings: list[Finding], attack_paths: list[AttackPath]) -> str:
        """Produce developer technical summary text."""
        affected_files = len({f.file_path for f in findings})
        rules_triggered = len({f.rule_id for f in findings})
        summary = (
            f"Found {len(findings)} unique findings affecting {affected_files} files across {rules_triggered} security rules. "
            f"Correlated {len(attack_paths)} multi-step attack paths reaching vulnerable sinks. "
            f"Immediate focus should be directed toward top-risk entry points."
        )
        return summary


class SecurityReportService:
    """Constructs comprehensive normalized SecurityReport entity."""

    @staticmethod
    def create_report(
        findings: list[Finding],
        attack_paths: list[AttackPath],
        posture: SecurityPosture,
        scan_metadata: ScanMetadata,
        analysis_metadata: AnalysisMetadata,
        health: AnalysisHealth | None = None,
        performance: PerformanceMetrics | None = None,
    ) -> SecurityReport:
        """Assemble full SecurityReport entity."""
        stats = SecurityMetricsService.build_statistics(findings)
        components = SecurityMetricsService.build_component_metrics(findings)
        remediations = SecurityMetricsService.build_remediation_priorities(findings)

        exec_sum = SecurityMetricsService.generate_executive_summary(posture, stats)
        dev_sum = SecurityMetricsService.generate_developer_summary(findings, attack_paths)

        scores = [f.risk_score for f in findings]
        risk_metrics = RiskMetrics(
            project_risk_score=posture.project_risk_score,
            highest_finding_score=max(scores) if scores else 0.0,
            average_risk_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
            critical_attack_paths=len([ap for ap in attack_paths if ap.risk_score >= 80]),
            high_risk_components=[c.name for c in components if c.risk_score >= 60],
        )

        return SecurityReport(
            scan_metadata=scan_metadata,
            analysis_metadata=analysis_metadata,
            statistics=stats,
            risk_metrics=risk_metrics,
            posture=posture,
            health=health or AnalysisHealth(),
            performance=performance or PerformanceMetrics(),
            findings=findings,
            attack_paths=attack_paths,
            components=components,
            remediation_priorities=remediations,
            executive_summary=exec_sum,
            developer_summary=dev_sum,
        )


class TrendService:
    """Prepares structured DashboardSnapshot datasets."""

    @staticmethod
    def create_dashboard_snapshot(report: SecurityReport) -> DashboardSnapshot:
        """Export report into dashboard-ready snapshot contract."""
        return DashboardSnapshot(
            summary={
                "scan_id": report.scan_metadata.scan_id,
                "project_name": report.scan_metadata.project_name,
                "project_risk_score": report.risk_metrics.project_risk_score,
                "policy_passed": report.posture.policy_passed,
                "policy_violations": report.posture.policy_violations,
                "total_findings": report.statistics.total_findings,
            },
            severity_distribution={
                "CRITICAL": report.statistics.critical_count,
                "HIGH": report.statistics.high_count,
                "MEDIUM": report.statistics.medium_count,
                "LOW": report.statistics.low_count,
                "INFO": report.statistics.info_count,
            },
            component_risk=[
                {
                    "name": c.name,
                    "risk_score": c.risk_score,
                    "total_findings": c.total_findings,
                    "critical": c.critical_count,
                    "high": c.high_count,
                }
                for c in report.components
            ],
            top_rules=[
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "risk_score": r.risk_score,
                }
                for r in report.remediation_priorities
            ],
            attack_paths=[
                {
                    "id": ap.id,
                    "title": ap.title,
                    "type": ap.attack_type.value,
                    "risk_score": ap.risk_score,
                }
                for ap in report.attack_paths
            ],
            policy_status={
                "passed": report.posture.policy_passed,
                "violations": report.posture.policy_violations,
            },
        )
