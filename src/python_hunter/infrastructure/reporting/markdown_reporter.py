"""Markdown Security Reporter."""

from typing import Any

from python_hunter.domain.reporting.models import SecurityReport
from python_hunter.infrastructure.reporting.base import BaseReporter, ReporterRegistry
from python_hunter.infrastructure.reporting.redaction import SecretRedactor


class MarkdownReporter(BaseReporter):
    """Generates rich GitHub Flavored Markdown security reports."""

    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport into GFM Markdown string."""
        opts = options or {}
        redact = opts.get("redact_secrets", True)
        findings = SecretRedactor.redact_findings(report.findings, enabled=redact)

        lines: list[str] = []
        lines.append(f"# Security Intelligence Report — {report.scan_metadata.project_name or report.scan_metadata.project_path}\n")

        # Executive Summary Alert Card
        gate_icon = "✅ PASSED" if report.posture.policy_passed else "❌ FAILED"
        lines.append("> [!IMPORTANT]")
        lines.append(f"> **Project Risk Score**: `{report.risk_metrics.project_risk_score}/100` | **Security Gate**: **{gate_icon}**")
        lines.append(f">\n> {report.executive_summary}\n")

        # Overview Table
        lines.append("## Overview Metadata\n")
        lines.append("| Metric | Value |")
        lines.append("|---|---|")
        lines.append(f"| **Target Path** | `{report.scan_metadata.project_path}` |")
        lines.append(f"| **Scanner Version** | `{report.scan_metadata.scanner_version}` |")
        lines.append(f"| **Total Findings** | `{report.statistics.total_findings}` |")
        lines.append(f"| **Correlated Attack Paths** | `{len(report.attack_paths)}` |")
        if report.scan_metadata.commit_sha:
            lines.append(f"| **Commit SHA** | `{report.scan_metadata.commit_sha}` |")
        lines.append("")

        # Severity Breakdown Table
        lines.append("## Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        lines.append(f"| 🚨 **CRITICAL** | {report.statistics.critical_count} |")
        lines.append(f"| 🔴 **HIGH** | {report.statistics.high_count} |")
        lines.append(f"| 🟡 **MEDIUM** | {report.statistics.medium_count} |")
        lines.append(f"| 🔵 **LOW** | {report.statistics.low_count} |")
        lines.append(f"| ℹ️ **INFO** | {report.statistics.info_count} |")
        lines.append("")

        # Attack Paths Section
        if report.attack_paths:
            lines.append("## Correlated Attack Paths\n")
            lines.append("| Attack Type | Title | Entry Point | Target Sink | Risk Score |")
            lines.append("|---|---|---|---|---|")
            for ap in report.attack_paths:
                lines.append(f"| `{ap.attack_type.value}` | {ap.title} | `{ap.entry_point}` | `{ap.target_sink}` | `{ap.risk_score}` |")
            lines.append("")

        # Component Risk Breakdown
        if report.components:
            lines.append("## Component Risk Breakdown\n")
            lines.append("| Component | Risk Score | Critical | High | Total Findings |")
            lines.append("|---|---|---|---|---|")
            for c in report.components:
                lines.append(f"| `{c.name}` | `{c.risk_score}` | {c.critical_count} | {c.high_count} | {c.total_findings} |")
            lines.append("")

        # Detailed Findings List
        lines.append("## Security Findings Detail\n")
        if not findings:
            lines.append("No security weaknesses detected.\n")
        else:
            for idx, f in enumerate(findings, 1):
                line_no = f.location.line_start if f.location else 0
                lines.append(f"### {idx}. [{f.severity.value}] {f.title} (`{f.rule_id}`)\n")
                lines.append(f"- **Location**: `{f.file_path}:{line_no}`")
                lines.append(f"- **Risk Score**: `{f.risk_score}` | **Category**: `{f.category.value}` | **Status**: `{f.lifecycle_state.value}`")
                lines.append(f"- **Description**: {f.description}")
                if f.evidence:
                    lines.append(f"- **Evidence**: `{f.evidence}`")
                if f.secondary_evidence:
                    lines.append(f"- **Correlated Evidence**: {', '.join([f'`{s}`' for s in f.secondary_evidence])}")
                lines.append(f"- **Remediation**: {f.remediation}\n")

        # Prioritized Remediation Roadmap
        if report.remediation_priorities:
            lines.append("## Remediation Roadmap Priorities\n")
            lines.append("| Priority | Rule ID | Title | File & Line | Risk Score |")
            lines.append("|---|---|---|---|---|")
            for r in report.remediation_priorities:
                lines.append(f"| **#{r.priority_level}** | `{r.rule_id}` | {r.title} | `{r.file_path}:{r.line}` | `{r.risk_score}` |")
            lines.append("")

        return "\n".join(lines)


ReporterRegistry.register("markdown", MarkdownReporter)
ReporterRegistry.register("md", MarkdownReporter)
