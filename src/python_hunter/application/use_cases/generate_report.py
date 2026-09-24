"""Generate Report Application Use Case.

Supports both CI artifact rendering and modern executive/compliance security reports.
"""

from datetime import datetime, timezone
import json
import os
import platform
import sys
import time
import uuid
from typing import Any

from python_hunter import __version__
from python_hunter.application.orchestrator.scan_context import ScanResult
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.compliance.assessment import ComplianceAssessmentEngine
from python_hunter.domain.compliance.models import ComplianceControlModel
from python_hunter.domain.compliance.registry import ControlRegistry
from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.policy.engine import SecurityPolicyEngine
from python_hunter.domain.reporting.dashboard_services import (
    FindingQueryService,
    SecurityMetricsService,
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

# Import reporters to ensure registration in ReporterRegistry
import python_hunter.infrastructure.reporting.csv_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.html_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.json_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.markdown_reporter  # noqa: F401
import python_hunter.infrastructure.reporting.sarif_exporter  # noqa: F401
import python_hunter.infrastructure.reporting.terminal  # noqa: F401


class GenerateReportUseCase:
    """Orchestrates security report generation, filtering, risk posture evaluation, and export."""

    def __init__(
        self,
        security_use_case: AnalyzeSecurityUseCase | None = None,
        orchestrator: ScanOrchestrator | None = None,
    ) -> None:
        self.security_use_case = security_use_case or AnalyzeSecurityUseCase()
        self.orchestrator = orchestrator or ScanOrchestrator()
        self.control_registry = ControlRegistry()
        self.assessment_engine = ComplianceAssessmentEngine(registry=self.control_registry)

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

    def generate_executive_report(
        self,
        target_path: str,
        report_type: str = "executive",
        format_type: str = "html",
        framework_id: str = "OWASP_TOP_10",
        organization: str = "Enterprise Security",
        title: str | None = None,
        scan_result: ScanResult | None = None,
    ) -> dict[str, Any]:
        """Generate visual executive and compliance security reports."""
        local_target = target_path if os.path.exists(target_path) else "."
        result = scan_result or self.orchestrator.run_scan(local_target)

        fw_id = self._normalize_framework_id(framework_id)

        assessment = self.assessment_engine.create_assessment(
            framework_id=fw_id,
            assessor="Python Hunter Automated Engine",
            organization_id=organization,
        )
        compliance_eval = self.assessment_engine.evaluate_controls(
            assessment_id=assessment.assessment_id,
            findings=result.findings,
        )

        compliance_score = compliance_eval.get("overall_score", 100.0)
        compliance_grade = self._calculate_grade(compliance_score)

        stats = SecurityMetricsService.build_statistics(result.findings)
        components = SecurityMetricsService.build_component_metrics(result.findings)
        remediations = SecurityMetricsService.build_remediation_priorities(result.findings)

        risk_score = result.project_risk.overall_score if result.project_risk else 0.0
        policy_passed = result.exit_code == 0

        malware_findings = [
            f for f in result.findings
            if getattr(f, "category", None) and f.category.value == "MALWARE_RISK"
        ]
        secret_findings = [
            f for f in result.findings
            if getattr(f, "category", None) and f.category.value == "SECRET_LEAK"
        ]
        supply_findings = [
            f for f in result.findings
            if getattr(f, "category", None)
            and f.category.value in ("SUPPLY_CHAIN", "VULNERABLE_DEPENDENCY", "DEPENDENCY")
        ]
        ast_findings = [
            f for f in result.findings
            if f not in malware_findings and f not in secret_findings and f not in supply_findings
        ]

        report_title = title or f"Executive Security Assurance Report: {os.path.basename(os.path.abspath(local_target))}"
        fmt = (format_type or "html").lower()

        data_bundle = {
            "title": report_title,
            "report_type": report_type.lower(),
            "target": local_target,
            "organization": organization,
            "framework_id": fw_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "risk_score": risk_score,
            "policy_passed": policy_passed,
            "compliance_score": compliance_score,
            "compliance_grade": compliance_grade,
            "compliance_eval": compliance_eval,
            "stats": stats,
            "findings_count": len(result.findings),
            "malware_count": len(malware_findings),
            "secret_count": len(secret_findings),
            "supply_count": len(supply_findings),
            "ast_count": len(ast_findings),
            "remediations": remediations,
            "components": components,
            "findings": result.findings,
        }

        if fmt == "json":
            content = self._render_json(data_bundle)
        elif fmt in ("markdown", "md"):
            content = self._render_markdown(data_bundle)
        else:
            content = self._render_html(data_bundle)

        return {
            "title": report_title,
            "report_type": report_type.lower(),
            "format": fmt,
            "risk_score": risk_score,
            "compliance_grade": compliance_grade,
            "compliance_score": compliance_score,
            "findings_count": len(result.findings),
            "content": content,
        }

    def execute(
        self,
        target_path: str,
        format_name: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        component: str | None = None,
        status: str | None = None,
        confidence: str | None = None,
        sort_by: str = "risk",
        limit: int | None = None,
        options: dict[str, Any] | None = None,
        report_type: str | None = None,
        format_type: str | None = None,
        framework_id: str = "OWASP_TOP_10",
        organization: str = "Enterprise Security",
        title: str | None = None,
    ) -> Any:
        """Execute report generation supporting both CI export strings and executive report dicts."""
        # If explicitly called with executive report parameters, generate executive report dict
        if report_type is not None or format_type is not None:
            return self.generate_executive_report(
                target_path=target_path,
                report_type=report_type or "executive",
                format_type=format_type or "html",
                framework_id=framework_id,
                organization=organization,
                title=title,
            )

        # Standard CI / ReporterRegistry pipeline (returns rendered string)
        fmt = format_name or "terminal"
        report = self.build_report(target_path)

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

        reporter = ReporterRegistry.get(fmt)
        return reporter.render(report, options=options)

    @staticmethod
    def _normalize_framework_id(name: str) -> str:
        norm = name.strip().upper().replace("-", "_")
        aliases = {
            "OWASP_TOP_10": "OWASP_TOP_10",
            "OWASP": "OWASP_TOP_10",
            "OWASP_ASVS": "OWASP_ASVS_V4",
            "NIST": "NIST_CSF_V2",
            "SOC2": "SOC_2_TYPE_2",
            "SOC_2": "SOC_2_TYPE_2",
            "ISO27001": "ISO_27001_2022",
            "CIS": "CIS_CONTROLS_V8",
        }
        return aliases.get(norm, norm)

    @staticmethod
    def _calculate_grade(score: float) -> str:
        if score >= 90.0:
            return "A"
        elif score >= 80.0:
            return "B"
        elif score >= 70.0:
            return "C"
        elif score >= 60.0:
            return "D"
        return "F"

    def _render_html(self, d: dict[str, Any]) -> str:
        """Render modern, responsive executive HTML report."""
        risk_color = "#ef4444" if d["risk_score"] >= 70.0 else ("#f59e0b" if d["risk_score"] >= 40.0 else "#10b981")
        gate_color = "#10b981" if d["policy_passed"] else "#ef4444"
        gate_text = "PASSED" if d["policy_passed"] else "FAILED"
        grade_color = "#10b981" if d["compliance_grade"] in ("A", "B") else ("#f59e0b" if d["compliance_grade"] == "C" else "#ef4444")

        rem_rows = []
        for r in d["remediations"]:
            rem_rows.append(
                f"""<tr>
                  <td style="font-weight:bold;text-align:center;">#{r.priority_level}</td>
                  <td><code>{r.rule_id}</code></td>
                  <td><strong>{r.title}</strong><br><span style="color:#94a3b8;font-size:12px;">{r.file_path}:{r.line}</span></td>
                  <td><span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">{r.risk_score:.1f}</span></td>
                  <td style="color:#cbd5e1;font-size:13px;">{r.remediation_text}</td>
                </tr>"""
            )

        ctrl_rows = []
        for c in d["compliance_eval"].get("evaluated_controls", []):
            st = c.get("state")
            state_str = st.value if hasattr(st, "value") else str(st)
            st_color = "#10b981" if state_str == "COMPLIANT" else ("#f59e0b" if state_str == "PARTIALLY_COMPLIANT" else "#ef4444")
            ctrl_rows.append(
                f"""<tr>
                  <td><code>{c.get('control_id')}</code></td>
                  <td>{c.get('title')}</td>
                  <td><span style="background:{st_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">{state_str}</span></td>
                  <td style="text-align:center;">{c.get('findings_count', 0)}</td>
                </tr>"""
            )

        findings_rows = []
        for f in d["findings"][:50]:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            s_color = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else ("#d97706" if sev == "MEDIUM" else "#16a34a"))
            line_no = f.location.line_start if f.location else 1
            findings_rows.append(
                f"""<tr>
                  <td><span style="background:{s_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">{sev}</span></td>
                  <td><code>{f.rule_id}</code></td>
                  <td><strong>{f.title}</strong><br><span style="color:#94a3b8;font-size:11px;">{f.file_path}:{line_no}</span></td>
                  <td style="font-family:monospace;font-size:12px;color:#cbd5e1;">{f.evidence or '-'}</td>
                </tr>"""
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{d['title']}</title>
  <style>
    :root {{
      --bg: #0b1120;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .header h1 {{ margin: 0 0 6px 0; font-size: 24px; color: #fff; }}
    .header .meta {{ color: var(--text-muted); font-size: 13px; }}
    .badge-org {{ background: #0284c7; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
    
    .grid-kpi {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .kpi-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
      text-align: center;
    }}
    .kpi-label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 6px; }}
    .kpi-value {{ font-size: 28px; font-weight: 800; }}
    .kpi-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}

    .grid-domains {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .domain-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
    }}
    .domain-title {{ font-size: 14px; font-weight: 700; margin-bottom: 8px; display: flex; justify-content: space-between; }}

    .section-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 24px;
    }}
    .section-card h2 {{ margin-top: 0; font-size: 18px; border-bottom: 1px solid var(--card-border); padding-bottom: 12px; }}

    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #27354a; font-size: 13px; }}
    th {{ background: #0f172a; color: var(--text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; }}
    .footer {{ text-align: center; color: var(--text-muted); font-size: 12px; padding: 20px 0; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>{d['title']}</h1>
        <div class="meta">
          Organization: <span class="badge-org">{d['organization']}</span> &nbsp;|&nbsp;
          Target: <code>{d['target']}</code> &nbsp;|&nbsp;
          Timestamp: {d['timestamp']}
        </div>
      </div>
      <div>
        <span style="background:{gate_color};color:#fff;padding:8px 18px;border-radius:8px;font-weight:800;font-size:16px;">
          POLICY GATE {gate_text}
        </span>
      </div>
    </div>

    <div class="grid-kpi">
      <div class="kpi-card">
        <div class="kpi-label">Project Risk Score</div>
        <div class="kpi-value" style="color:{risk_color};">{d['risk_score']:.1f}<span style="font-size:14px;color:#94a3b8;">/100</span></div>
        <div class="kpi-sub">{"High Risk" if d['risk_score']>=70 else ("Medium Risk" if d['risk_score']>=40 else "Low Risk")}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Compliance Grade</div>
        <div class="kpi-value" style="color:{grade_color};">Grade {d['compliance_grade']}</div>
        <div class="kpi-sub">{d['compliance_score']:.1f}% ({d['framework_id']})</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Critical / High Issues</div>
        <div class="kpi-value" style="color:#ef4444;">{d['stats'].critical_count + d['stats'].high_count}</div>
        <div class="kpi-sub">{d['stats'].critical_count} Critical, {d['stats'].high_count} High</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Findings</div>
        <div class="kpi-value" style="color:var(--accent);">{d['findings_count']}</div>
        <div class="kpi-sub">{d['stats'].medium_count} Med, {d['stats'].low_count} Low</div>
      </div>
    </div>

    <div class="grid-domains">
      <div class="domain-card">
        <div class="domain-title">
          <span>Malware & Integrity</span>
          <span style="color:{'#ef4444' if d['malware_count']>0 else '#10b981'}; font-weight:bold;">
            {d['malware_count']} Threat(s)
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">PolinRider, tasks jacking, wipers, and trojan fonts.</div>
      </div>
      <div class="domain-card">
        <div class="domain-title">
          <span>Secrets & Credentials</span>
          <span style="color:{'#ef4444' if d['secret_count']>0 else '#10b981'}; font-weight:bold;">
            {d['secret_count']} Leak(s)
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">API tokens, private keys, database passwords.</div>
      </div>
      <div class="domain-card">
        <div class="domain-title">
          <span>Supply-Chain & SCA</span>
          <span style="color:{'#f59e0b' if d['supply_count']>0 else '#10b981'}; font-weight:bold;">
            {d['supply_count']} Issue(s)
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">Typosquatting, unpinned packages, hook injections.</div>
      </div>
      <div class="domain-card">
        <div class="domain-title">
          <span>SAST & Code Vulnerabilities</span>
          <span style="color:{'#f59e0b' if d['ast_count']>0 else '#10b981'}; font-weight:bold;">
            {d['ast_count']} Vulnerability(ies)
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">Injection sinks, command execution, insecure deserialization.</div>
      </div>
    </div>

    <div class="section-card">
      <h2>Top Remediation Priorities (Actionable Roadmap)</h2>
      <table>
        <thead>
          <tr>
            <th style="width:40px;">#</th>
            <th>Rule ID</th>
            <th>Security Finding & Location</th>
            <th>Risk</th>
            <th>Remediation Action</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rem_rows) if rem_rows else '<tr><td colspan="5">No pending remediation priorities.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <h2>Compliance Benchmark Audit ({d['framework_id']})</h2>
      <table>
        <thead>
          <tr>
            <th>Control ID</th>
            <th>Control Title</th>
            <th>Status</th>
            <th style="text-align:center;">Violations</th>
          </tr>
        </thead>
        <tbody>
          {''.join(ctrl_rows) if ctrl_rows else '<tr><td colspan="4">No controls assessed.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <h2>Complete Findings Inventory ({min(50, d['findings_count'])})</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule ID</th>
            <th>Finding & Location</th>
            <th>Evidence Snippet</th>
          </tr>
        </thead>
        <tbody>
          {''.join(findings_rows) if findings_rows else '<tr><td colspan="4">Zero security findings detected.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Generated by Python Hunter v{__version__} Security Assurance Platform &bull; Automated Defense & Compliance
    </div>
  </div>
</body>
</html>"""

    def _render_markdown(self, d: dict[str, Any]) -> str:
        """Render GitHub-ready Markdown executive report."""
        gate_status = "PASSED" if d["policy_passed"] else "FAILED"
        lines = [
            f"# {d['title']}",
            "",
            f"**Organization:** {d['organization']} | **Target:** `{d['target']}` | **Date:** {d['timestamp']}",
            f"**Policy Gate:** `{gate_status}` | **Risk Score:** `{d['risk_score']:.1f}/100` | **Compliance:** Grade `{d['compliance_grade']}` ({d['compliance_score']:.1f}%)",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"- **Overall Risk Score:** `{d['risk_score']:.1f}/100`",
            f"- **Total Security Issues:** `{d['findings_count']}` (Critical: `{d['stats'].critical_count}`, High: `{d['stats'].high_count}`, Medium: `{d['stats'].medium_count}`, Low: `{d['stats'].low_count}`)",
            f"- **Malware Threats:** `{d['malware_count']}`",
            f"- **Credential Leaks:** `{d['secret_count']}`",
            f"- **Supply-Chain & SCA Risks:** `{d['supply_count']}`",
            f"- **SAST & AST Vulnerabilities:** `{d['ast_count']}`",
            "",
            "---",
            "",
            "## 2. Top Remediation Priorities",
            "| Priority | Rule ID | Title | File / Line | Remediation |",
            "|---|---|---|---|---|",
        ]
        for r in d["remediations"]:
            lines.append(f"| #{r.priority_level} | `{r.rule_id}` | {r.title} | `{r.file_path}:{r.line}` | {r.remediation_text} |")

        lines.extend([
            "",
            "---",
            "",
            f"## 3. Compliance Framework Benchmark ({d['framework_id']})",
            "| Control ID | Title | Status | Violations |",
            "|---|---|---|---|",
        ])
        for c in d["compliance_eval"].get("evaluated_controls", []):
            st = c.get("state")
            state_str = st.value if hasattr(st, "value") else str(st)
            lines.append(f"| `{c.get('control_id')}` | {c.get('title')} | `{state_str}` | {c.get('findings_count', 0)} |")

        lines.extend([
            "",
            "---",
            f"*Generated by Python Hunter v{__version__} Security Intelligence Platform*",
        ])
        return "\n".join(lines)

    def _render_json(self, d: dict[str, Any]) -> str:
        """Render JSON export."""
        export_dict = {
            "title": d["title"],
            "report_type": d["report_type"],
            "organization": d["organization"],
            "target": d["target"],
            "timestamp": d["timestamp"],
            "risk_score": d["risk_score"],
            "policy_passed": d["policy_passed"],
            "compliance_grade": d["compliance_grade"],
            "compliance_score": d["compliance_score"],
            "framework_id": d["framework_id"],
            "statistics": {
                "total": d["findings_count"],
                "critical": d["stats"].critical_count,
                "high": d["stats"].high_count,
                "medium": d["stats"].medium_count,
                "low": d["stats"].low_count,
                "info": d["stats"].info_count,
            },
            "domain_breakdown": {
                "malware": d["malware_count"],
                "secrets": d["secret_count"],
                "supply_chain": d["supply_count"],
                "sast": d["ast_count"],
            },
            "compliance_controls": [
                {
                    "control_id": c.get("control_id"),
                    "title": c.get("title"),
                    "state": c.get("state").value if hasattr(c.get("state"), "value") else str(c.get("state")),
                    "findings_count": c.get("findings_count", 0),
                }
                for c in d["compliance_eval"].get("evaluated_controls", [])
            ],
            "top_remediations": [
                {
                    "priority": r.priority_level,
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "file": r.file_path,
                    "line": r.line,
                    "risk_score": r.risk_score,
                    "remediation": r.remediation_text,
                }
                for r in d["remediations"]
            ],
            "findings_count": len(d["findings"]),
        }
        return json.dumps(export_dict, indent=2)
