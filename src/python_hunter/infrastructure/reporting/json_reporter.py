"""Deterministic Versioned JSON Reporter."""

import json
from typing import Any

from python_hunter.domain.reporting.models import SecurityReport
from python_hunter.infrastructure.reporting.base import BaseReporter, ReporterRegistry
from python_hunter.infrastructure.reporting.redaction import SecretRedactor


class JsonReporter(BaseReporter):
    """Generates machine-readable deterministic JSON security reports."""

    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport into deterministic versioned JSON string."""
        opts = options or {}
        redact = opts.get("redact_secrets", True)
        indent = opts.get("indent", 2)

        findings = SecretRedactor.redact_findings(report.findings, enabled=redact)

        data: dict[str, Any] = {
            "schema_version": report.schema_version,
            "scan_metadata": {
                "scan_id": report.scan_metadata.scan_id,
                "project_name": report.scan_metadata.project_name,
                "project_path": report.scan_metadata.project_path,
                "scanner_version": report.scan_metadata.scanner_version,
                "timestamp": report.scan_metadata.timestamp,
                "duration_seconds": report.scan_metadata.duration_seconds,
                "configuration_hash": report.scan_metadata.configuration_hash,
                "commit_sha": report.scan_metadata.commit_sha,
                "branch": report.scan_metadata.branch,
            },
            "analysis_metadata": {
                "python_version": report.analysis_metadata.python_version,
                "operating_system": report.analysis_metadata.operating_system,
                "enabled_analyzers": report.analysis_metadata.enabled_analyzers,
                "disabled_analyzers": report.analysis_metadata.disabled_analyzers,
                "rule_set_version": report.analysis_metadata.rule_set_version,
                "configuration": report.analysis_metadata.configuration,
            },
            "statistics": {
                "total_findings": report.statistics.total_findings,
                "critical_count": report.statistics.critical_count,
                "high_count": report.statistics.high_count,
                "medium_count": report.statistics.medium_count,
                "low_count": report.statistics.low_count,
                "info_count": report.statistics.info_count,
                "new_count": report.statistics.new_count,
                "existing_count": report.statistics.existing_count,
                "resolved_count": report.statistics.resolved_count,
                "reopened_count": report.statistics.reopened_count,
                "suppressed_count": report.statistics.suppressed_count,
            },
            "risk_metrics": {
                "project_risk_score": report.risk_metrics.project_risk_score,
                "highest_finding_score": report.risk_metrics.highest_finding_score,
                "average_risk_score": report.risk_metrics.average_risk_score,
                "critical_attack_paths": report.risk_metrics.critical_attack_paths,
                "high_risk_components": report.risk_metrics.high_risk_components,
            },
            "posture": {
                "policy_passed": report.posture.policy_passed,
                "policy_violations": report.posture.policy_violations,
                "project_risk_score": report.posture.project_risk_score,
            },
            "health": {
                "status": report.health.status,
                "complete": report.health.complete,
                "failed_analyzers": report.health.failed_analyzers,
                "warnings": report.health.warnings,
            },
            "performance": {
                "duration_seconds": report.performance.duration_seconds,
                "parsing_time": report.performance.parsing_time,
                "ast_analysis_time": report.performance.ast_analysis_time,
                "taint_analysis_time": report.performance.taint_analysis_time,
                "correlation_time": report.performance.correlation_time,
            },
            "components": [
                {
                    "name": c.name,
                    "risk_score": c.risk_score,
                    "total_findings": c.total_findings,
                    "critical_count": c.critical_count,
                    "high_count": c.high_count,
                }
                for c in report.components
            ],
            "attack_paths": [
                {
                    "id": ap.id,
                    "title": ap.title,
                    "type": ap.attack_type.value,
                    "entry_point": ap.entry_point,
                    "target_sink": ap.target_sink,
                    "risk_score": ap.risk_score,
                }
                for ap in report.attack_paths
            ],
            "findings": [
                {
                    "finding_id": f.fingerprint,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "category": f.category.value,
                    "risk_score": f.risk_score,
                    "exposure": f.exposure.value,
                    "reachability": f.reachability.value,
                    "lifecycle_state": f.lifecycle_state.value,
                    "file_path": f.file_path,
                    "line": f.location.line_start if f.location else 0,
                    "column": f.location.column_start if f.location else 0,
                    "evidence": f.evidence,
                    "source": f.source,
                    "sink": f.sink,
                    "secondary_evidence": f.secondary_evidence,
                    "remediation": f.remediation,
                    "fingerprint": f.fingerprint,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=indent)


ReporterRegistry.register("json", JsonReporter)
