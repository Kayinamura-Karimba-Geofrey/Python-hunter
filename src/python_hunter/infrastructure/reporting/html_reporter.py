"""Standalone Single-File HTML Security Reporter."""

import html
from typing import Any

from python_hunter.domain.reporting.models import SecurityReport
from python_hunter.infrastructure.reporting.base import BaseReporter, ReporterRegistry
from python_hunter.infrastructure.reporting.redaction import SecretRedactor


class HtmlReporter(BaseReporter):
    """Generates a modern, self-contained HTML security report."""

    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport into single-file HTML document."""
        opts = options or {}
        redact = opts.get("redact_secrets", True)
        findings = SecretRedactor.redact_findings(report.findings, enabled=redact)

        gate_status = "PASSED" if report.posture.policy_passed else "FAILED"
        gate_class = "pass" if report.posture.policy_passed else "fail"
        proj_name = html.escape(report.scan_metadata.project_name or report.scan_metadata.project_path)

        sev_rows = ""
        for f in findings:
            line_no = f.location.line_start if f.location else 0
            sev_class = f.severity.value.lower()
            ev_html = f"<div><strong>Evidence:</strong> <code>{html.escape(f.evidence)}</code></div>" if f.evidence else ""
            rem_html = f"<div><strong>Remediation:</strong> {html.escape(f.remediation)}</div>" if f.remediation else ""

            sev_rows += f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="badge {sev_class}">{f.severity.value}</span>
                    <span class="rule-id">{html.escape(f.rule_id)}</span>
                    <span class="title">{html.escape(f.title)}</span>
                    <span class="risk-pill">Risk {int(f.risk_score)}</span>
                </div>
                <div class="finding-body">
                    <div class="loc">📍 <code>{html.escape(f.file_path)}:{line_no}</code> | Category: <code>{f.category.value}</code></div>
                    <div class="desc">{html.escape(f.description)}</div>
                    {ev_html}
                    {rem_html}
                </div>
            </div>
            """

        ap_rows = ""
        for ap in report.attack_paths:
            ap_rows += f"""
            <tr>
                <td><span class="badge critical">{ap.attack_type.value}</span></td>
                <td>{html.escape(ap.title)}</td>
                <td><code>{html.escape(ap.entry_point)}</code></td>
                <td><code>{html.escape(ap.target_sink)}</code></td>
                <td><strong>{int(ap.risk_score)}</strong></td>
            </tr>
            """

        comp_rows = ""
        for c in report.components:
            comp_rows += f"""
            <tr>
                <td><code>{html.escape(c.name)}</code></td>
                <td><strong>{c.risk_score}</strong></td>
                <td>{c.critical_count}</td>
                <td>{c.high_count}</td>
                <td>{c.total_findings}</td>
            </tr>
            """

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Hunter Security Report — {proj_name}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --pass: #22c55e;
            --fail: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--bg-card); padding-bottom: 1rem; margin-bottom: 2rem; }}
        h1 {{ margin: 0; font-size: 1.8rem; font-weight: 700; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background-color: var(--bg-secondary); border-radius: 10px; padding: 1.5rem; border: 1px solid var(--bg-card); }}
        .card .title {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .card .value {{ font-size: 2.2rem; font-weight: 800; margin-top: 0.5rem; }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; color: #fff; }}
        .badge.critical {{ background-color: var(--critical); }}
        .badge.high {{ background-color: var(--high); }}
        .badge.medium {{ background-color: var(--medium); color: #000; }}
        .badge.low {{ background-color: var(--low); }}
        .badge.info {{ background-color: var(--info); }}
        .status-badge {{ display: inline-block; padding: 0.4rem 1rem; border-radius: 20px; font-weight: 800; font-size: 0.9rem; }}
        .status-badge.pass {{ background-color: rgba(34, 197, 94, 0.2); color: var(--pass); border: 1px solid var(--pass); }}
        .status-badge.fail {{ background-color: rgba(239, 68, 68, 0.2); color: var(--fail); border: 1px solid var(--fail); }}
        .finding-card {{ background-color: var(--bg-secondary); border-radius: 8px; margin-bottom: 1rem; padding: 1rem; border-left: 5px solid var(--info); }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-header {{ display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap; margin-bottom: 0.5rem; }}
        .finding-header .title {{ font-weight: 600; font-size: 1.1rem; flex-grow: 1; }}
        .finding-header .risk-pill {{ background: var(--bg-card); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
        .finding-body {{ font-size: 0.95rem; line-height: 1.5; color: var(--text-muted); }}
        .finding-body code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 4px; color: #38bdf8; font-family: monospace; }}
        .finding-body div {{ margin-top: 0.4rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: var(--bg-secondary); border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 0.8rem 1rem; text-align: left; border-bottom: 1px solid var(--bg-card); font-size: 0.9rem; }}
        th {{ background-color: #1e293b; color: var(--text-muted); font-weight: 600; }}
        section {{ margin-bottom: 2.5rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Python Hunter Security Intelligence</h1>
                <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.2rem;">Project: {proj_name} | Path: <code>{html.escape(report.scan_metadata.project_path)}</code></div>
            </div>
            <div>
                <span class="status-badge {gate_class}">GATE {gate_status}</span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="title">Project Risk Score</div>
                <div class="value" style="color: {'#ef4444' if report.risk_metrics.project_risk_score >= 60 else '#22c55e'};">{report.risk_metrics.project_risk_score}/100</div>
            </div>
            <div class="card">
                <div class="title">Total Findings</div>
                <div class="value">{report.statistics.total_findings}</div>
            </div>
            <div class="card">
                <div class="title">Critical & High</div>
                <div class="value" style="color: var(--high);">{report.statistics.critical_count + report.statistics.high_count}</div>
            </div>
            <div class="card">
                <div class="title">Attack Paths</div>
                <div class="value">{len(report.attack_paths)}</div>
            </div>
        </div>

        {f'<section><h2>Correlated Attack Paths</h2><table><thead><tr><th>Type</th><th>Title</th><th>Entry Point</th><th>Target Sink</th><th>Risk</th></tr></thead><tbody>{ap_rows}</tbody></table></section>' if report.attack_paths else ''}

        {f'<section><h2>Component Risk Breakdown</h2><table><thead><tr><th>Component</th><th>Risk Score</th><th>Critical</th><th>High</th><th>Total Findings</th></tr></thead><tbody>{comp_rows}</tbody></table></section>' if report.components else ''}

        <section>
            <h2>Security Findings ({len(findings)})</h2>
            {sev_rows if findings else '<p>No security weaknesses detected.</p>'}
        </section>
    </div>
</body>
</html>
"""
        return html_doc


ReporterRegistry.register("html", HtmlReporter)
