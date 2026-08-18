"""Terminal Reporter for Human-Readable CLI Output."""

from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.reporting.models import SecurityReport
from python_hunter.infrastructure.reporting.base import BaseReporter, ReporterRegistry
from python_hunter.infrastructure.reporting.redaction import SecretRedactor


class TerminalReporter(BaseReporter):
    """Generates clean human-readable security reports for terminal display."""

    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport into formatted terminal text string."""
        opts = options or {}
        quiet = opts.get("quiet", False)
        verbose = opts.get("verbose", False)
        details = opts.get("details", False)
        redact = opts.get("redact_secrets", True)

        findings = SecretRedactor.redact_findings(report.findings, enabled=redact)

        # Quiet mode output for CI scripts
        if quiet:
            if report.posture.policy_passed:
                return "PASSED: 0 policy violations"
            return f"FAILED: {len(report.posture.policy_violations)} policy violations"

        lines: list[str] = []
        lines.append("==========================================================")
        lines.append(" Python Hunter Security Report")
        lines.append("==========================================================")
        lines.append(f"Project Name   : {report.scan_metadata.project_name or report.scan_metadata.project_path}")
        lines.append(f"Target Path    : {report.scan_metadata.project_path}")
        if report.scan_metadata.commit_sha:
            lines.append(f"Commit SHA     : {report.scan_metadata.commit_sha}")
        lines.append(f"Scanner Version: {report.scan_metadata.scanner_version}")
        lines.append("──────────────────────────────────────────────────────────")
        lines.append(f"Risk Score     : {report.risk_metrics.project_risk_score}/100")
        lines.append(f"Gate Status    : {'PASSED' if report.posture.policy_passed else 'FAILED'}")
        lines.append("──────────────────────────────────────────────────────────")
        lines.append(f"Findings       :")
        lines.append(f"  CRITICAL     : {report.statistics.critical_count}")
        lines.append(f"  HIGH         : {report.statistics.high_count}")
        lines.append(f"  MEDIUM       : {report.statistics.medium_count}")
        lines.append(f"  LOW          : {report.statistics.low_count}")
        lines.append(f"  INFO         : {report.statistics.info_count}")
        lines.append("──────────────────────────────────────────────────────────")
        lines.append(f"Attack Paths   : {len(report.attack_paths)}")
        lines.append(f"New Findings   : {report.statistics.new_count}")
        lines.append(f"Resolved       : {report.statistics.resolved_count}")
        lines.append("==========================================================")

        if report.posture.policy_violations:
            lines.append("\n[!] Security Policy Violations:")
            for v in report.posture.policy_violations:
                lines.append(f"  • {v}")

        # Table View
        lines.append("\n" + "─" * 70)
        lines.append(f"{'SEVERITY':<10} {'RISK':<6} {'RULE ID':<18} {'LOCATION':<24} {'STATUS':<10}")
        lines.append("─" * 70)

        if not findings:
            lines.append("No security weaknesses detected.")
        else:
            for f in findings:
                line_no = f.location.line_start if f.location else 0
                loc_str = f"{f.file_path}:{line_no}"
                if len(loc_str) > 23:
                    loc_str = loc_str[:20] + "..."
                lines.append(
                    f"{f.severity.value:<10} {int(f.risk_score):<6} {f.rule_id:<18} {loc_str:<24} {f.lifecycle_state.value:<10}"
                )

        lines.append("─" * 70)

        # Details View
        if details and findings:
            lines.append("\n==========================================================")
            lines.append(" Detailed Finding Evidence & Remediation")
            lines.append("==========================================================")
            for f in findings:
                line_no = f.location.line_start if f.location else 0
                lines.append(f"\n[+] {f.rule_id}: {f.title}")
                lines.append(f"    Severity   : {f.severity.value} (Risk Score: {f.risk_score})")
                lines.append(f"    Location   : {f.file_path}:{line_no}")
                lines.append(f"    Category   : {f.category.value}")
                lines.append(f"    Description: {f.description}")
                if f.evidence:
                    lines.append(f"    Evidence   : {f.evidence}")
                if f.source:
                    lines.append(f"    Source     : {f.source}")
                if f.sink:
                    lines.append(f"    Sink       : {f.sink}")
                if f.secondary_evidence:
                    lines.append(f"    Correlated : {'; '.join(f.secondary_evidence)}")
                lines.append(f"    Remediation: {f.remediation}")

        # Verbose Mode Output
        if verbose:
            lines.append("\n==========================================================")
            lines.append(" Verbose Analyzer Performance & Health Statistics")
            lines.append("==========================================================")
            lines.append(f"Health Status      : {report.health.status.upper()}")
            lines.append(f"Total Duration     : {report.performance.duration_seconds:.3f}s")
            lines.append(f"Parsing Time       : {report.performance.parsing_time:.3f}s")
            lines.append(f"AST Analysis Time  : {report.performance.ast_analysis_time:.3f}s")
            lines.append(f"Taint Analysis Time: {report.performance.taint_analysis_time:.3f}s")
            lines.append(f"Correlation Time   : {report.performance.correlation_time:.3f}s")
            if report.health.warnings:
                lines.append("\nWarnings:")
                for w in report.health.warnings:
                    lines.append(f"  • {w}")

        return "\n".join(lines)


ReporterRegistry.register("terminal", TerminalReporter)
ReporterRegistry.register("text", TerminalReporter)
