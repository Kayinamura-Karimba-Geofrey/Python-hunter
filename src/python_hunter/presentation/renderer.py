"""Terminal and JSON Output Renderers implementation."""

import json
from typing import Any
from python_hunter.application.orchestrator.scan_context import ScanResult


class OutputRenderer:
    """Base interface for CLI Output Renderers."""

    def render(self, result: ScanResult) -> str:
        raise NotImplementedError


class TerminalRenderer(OutputRenderer):
    """Renders professional rich colored terminal output summary."""

    def render(self, result: ScanResult) -> str:
        target_name = result.context.target.source if result.context.target else "Unknown"
        risk_score = result.project_risk.overall_score if result.project_risk else 0.0
        risk_str = "HIGH" if risk_score >= 70.0 else ("MEDIUM" if risk_score >= 40.0 else "LOW")
        paths_count = len(result.attack_paths)

        langs = ", ".join(result.context.options.get("detected_languages", ["python"]))
        lines = [
            "──────────────────────────────────────────────",
            "          PYTHON HUNTER SECURITY SCAN         ",
            "──────────────────────────────────────────────",
            f" Target:       {target_name}",
            f" Languages:    {langs}",
            f" Scan ID:      {result.context.scan_id}",
            f" Attack Paths: {paths_count}",
            f" Project Risk: {risk_str} ({risk_score:.1f}/100)",
            "──────────────────────────────────────────────",
        ]
        malware_findings = [f for f in result.findings if getattr(f, "category", None) and f.category.value == "MALWARE_RISK"]
        if malware_findings:
            lines.append("──────────────────────────────────────────────")
            lines.append(f" [!] MALWARE DETECTED: {len(malware_findings)} PolinRider / Supply-Chain Threats")
            lines.append("──────────────────────────────────────────────")
            for f in malware_findings:
                lines.append(f"  • [{f.severity.value}] {f.title}")
                lines.append(f"    File:     {f.file_path}")
                if f.evidence:
                    lines.append(f"    Evidence: {f.evidence[:70]}")
            lines.append("──────────────────────────────────────────────")

        cleanup = result.context.options.get("cleanup_result")
        if cleanup:
            lines.append("──────────────────────────────────────────────")
            lines.append("        AUTOMATED DISINFECTION APPLIED        ")
            lines.append("──────────────────────────────────────────────")
            lines.append(f" VS Code Tasks Disinfected:   {cleanup.tasks_sanitized}")
            lines.append(f" VS Code Settings Sanitized:  {cleanup.settings_sanitized}")
            lines.append(f" Dropper Scripts Deleted:     {len(cleanup.droppers_deleted)}")
            lines.append(f" Trojan Fonts Deleted:        {len(cleanup.trojan_fonts_deleted)}")
            lines.append(f" Build Configurations Cleaned:{len(cleanup.build_configs_cleaned)}")
            if cleanup.gitignore_cleaned:
                lines.append(" .gitignore Rules Restored:   YES")
            lines.append("──────────────────────────────────────────────")

        if result.exit_code != 0:
            lines.append(" Result:       [!] SECURITY POLICY VIOLATION FAILED")
        else:
            lines.append(" Result:       [✓] SECURITY SCAN PASSED")
        lines.append("──────────────────────────────────────────────")
        return "\n".join(lines)


class JsonRenderer(OutputRenderer):
    """Renders structured JSON report output."""

    def render(self, result: ScanResult) -> str:
        cleanup = result.context.options.get("cleanup_result")
        cleanup_data = None
        if cleanup:
            cleanup_data = {
                "tasks_sanitized": cleanup.tasks_sanitized,
                "settings_sanitized": cleanup.settings_sanitized,
                "droppers_deleted": cleanup.droppers_deleted,
                "trojan_fonts_deleted": cleanup.trojan_fonts_deleted,
                "build_configs_cleaned": cleanup.build_configs_cleaned,
                "gitignore_cleaned": cleanup.gitignore_cleaned,
            }

        data = {
            "scan_id": result.context.scan_id,
            "target": result.context.target.source if result.context.target else "",
            "target_type": result.context.target.target_type.value if result.context.target else "",
            "risk_score": result.project_risk.overall_score if result.project_risk else 0.0,
            "attack_paths_count": len(result.attack_paths),
            "findings_count": len(result.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "file_path": f.file_path,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
            "cleanup": cleanup_data,
            "exit_code": result.exit_code,
        }
        return json.dumps(data, indent=2)


class SarifRenderer(OutputRenderer):
    """Renders SARIF 2.1.0 format for GitHub Code Scanning."""

    def render(self, result: ScanResult) -> str:
        from python_hunter.infrastructure.reporting.sarif_exporter import SARIFExporter
        sarif_data = SARIFExporter.export(result.findings)
        return json.dumps(sarif_data, indent=2)


class MarkdownRenderer(OutputRenderer):
    """Renders formatted GitHub Flavored Markdown report."""

    def render(self, result: ScanResult) -> str:
        from python_hunter import __version__

        target_name = result.context.target.source if result.context.target else "Unknown"
        risk_score = result.project_risk.overall_score if result.project_risk else 0.0
        risk_str = "HIGH" if risk_score >= 70.0 else ("MEDIUM" if risk_score >= 40.0 else "LOW")
        status_str = "SECURITY POLICY VIOLATION" if result.exit_code != 0 else "SECURITY SCAN PASSED"

        lines = [
            "# Python Hunter Security Scan Report",
            "",
            f"- **Target:** `{target_name}`",
            f"- **Scan ID:** `{result.context.scan_id}`",
            f"- **Risk Posture:** **{risk_str}** ({risk_score:.1f}/100)",
            f"- **Status:** **{status_str}**",
            f"- **Findings Count:** {len(result.findings)}",
            "",
            "## Findings",
            "",
            "| Severity | Rule ID | Title | File Path |",
            "|---|---|---|---|",
        ]
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines.append(f"| **{sev}** | `{f.rule_id}` | {f.title} | `{f.file_path}` |")

        cleanup = result.context.options.get("cleanup_result")
        if cleanup:
            lines.extend([
                "",
                "## Disinfection & Remediation Applied",
                "",
                f"- **VS Code Tasks Disinfected:** {cleanup.tasks_sanitized}",
                f"- **VS Code Settings Sanitized:** {cleanup.settings_sanitized}",
                f"- **Dropper Scripts Removed:** {len(cleanup.droppers_deleted)}",
                f"- **Trojan Fonts Removed:** {len(cleanup.trojan_fonts_deleted)}",
                f"- **Build Configurations Cleaned:** {len(cleanup.build_configs_cleaned)}",
                f"- **Poisoned .gitignore Cleaned:** {'Yes' if cleanup.gitignore_cleaned else 'No'}",
            ])

        lines.extend([
            "",
            "---",
            f"*Generated by Python Hunter v{__version__}*",
        ])
        return "\n".join(lines)


class HtmlRenderer(OutputRenderer):
    """Renders standalone styled HTML security report."""

    def render(self, result: ScanResult) -> str:
        from python_hunter import __version__

        target_name = result.context.target.source if result.context.target else "Unknown"
        risk_score = result.project_risk.overall_score if result.project_risk else 0.0
        badge_color = "#dc2626" if risk_score >= 70.0 else ("#f59e0b" if risk_score >= 40.0 else "#16a34a")

        rows = []
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            color = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else "#d97706")
            rows.append(
                f"<tr><td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;'>{sev}</span></td>"
                f"<td><code>{f.rule_id}</code></td><td>{f.title}</td><td><code>{f.file_path}</code></td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Python Hunter Security Report - {target_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
    .card {{ background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 24px; }}
    h1 {{ margin: 0 0 16px 0; font-size: 24px; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; background: {badge_color}; color: #fff; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Python Hunter Security Scan</h1>
    <p>Target: <code>{target_name}</code> | Scan ID: <code>{result.context.scan_id}</code></p>
    <div>Risk Score: <span class="badge">{risk_score:.1f} / 100</span></div>
  </div>
  <div class="card">
    <h2>Security Findings ({len(result.findings)})</h2>
    <table>
      <thead><tr><th>Severity</th><th>Rule ID</th><th>Finding</th><th>Location</th></tr></thead>
      <tbody>
        {''.join(rows) if rows else '<tr><td colspan="4">No security vulnerabilities detected.</td></tr>'}
      </tbody>
    </table>
  </div>
  <p style="color:#64748b;font-size:12px;">Python Hunter v{__version__} Security Intelligence</p>
</body>
</html>"""
        return html


class CsvRenderer(OutputRenderer):
    """Renders CSV export format."""

    def render(self, result: ScanResult) -> str:
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Rule ID", "Severity", "Title", "File Path", "Line", "Evidence"])
        for f in result.findings:
            line_no = f.location.line_start if f.location else 1
            writer.writerow([
                f.rule_id,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                f.title,
                f.file_path,
                line_no,
                f.evidence or "",
            ])
        return output.getvalue().strip()


def get_renderer(format_name: str) -> OutputRenderer:
    """Factory helper returning appropriate OutputRenderer instance."""
    fmt = (format_name or "terminal").lower()
    if fmt == "sarif":
        return SarifRenderer()
    elif fmt in ("markdown", "md"):
        return MarkdownRenderer()
    elif fmt == "html":
        return HtmlRenderer()
    elif fmt == "csv":
        return CsvRenderer()
    elif fmt == "json":
        return JsonRenderer()
    return TerminalRenderer()

