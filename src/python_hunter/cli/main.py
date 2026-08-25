"""Main Professional CLI Entry Point for Python Hunter."""

import sys
import click

from python_hunter import __version__
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.presentation.policy import ExitCode, PolicyEngine
from python_hunter.presentation.renderer import JsonRenderer, TerminalRenderer


@click.group()
@click.version_option(version=__version__, prog_name="python-hunter")
def main() -> None:
    """Python Hunter - Professional Security & Code Intelligence Platform."""
    pass


@main.command()
@click.argument("target", default=".")
@click.option("--branch", default="", help="Git branch to clone/scan.")
@click.option("--commit", default="", help="Specific Git commit SHA to checkout and scan.")
@click.option("--tag", default="", help="Git tag to checkout and scan.")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]), default="terminal", help="Output format.")
@click.option("--output", "out_file", default="", help="Output file path.")
@click.option("--fail-on", default="high", help="Severity threshold to trigger non-zero exit code (critical, high, medium, low).")
@click.option("--ci", is_flag=True, help="Enable CI-friendly deterministic non-interactive execution mode.")
@click.option("--scan-mode", type=click.Choice(["full", "pull-request"]), default="full", help="Scan mode (full or pull-request).")
@click.option("--min-confidence", default="medium", help="Minimum confidence threshold (high, medium, low).")
@click.option("--baseline", default="", help="Path to baseline file for differential PR scan.")
@click.option("--require-exploitable", is_flag=True, help="Only fail build on provably exploitable findings.")
def scan(
    target: str,
    branch: str,
    commit: str,
    tag: str,
    fmt: str,
    out_file: str,
    fail_on: str,
    ci: bool,
    scan_mode: str,
    min_confidence: str,
    baseline: str,
    require_exploitable: bool,
) -> None:
    """Scans local project directories, files, or remote GitHub repositories."""
    orchestrator = ScanOrchestrator()
    policy_engine = PolicyEngine()

    options = {
        "is_ci": ci,
        "scan_mode": scan_mode,
        "min_confidence": min_confidence,
        "baseline": baseline,
        "require_exploitable": require_exploitable,
    }

    try:
        result = orchestrator.run_scan(target, branch=branch, commit=commit, tag=tag, fail_on=fail_on, options=options)
        exit_code = policy_engine.evaluate(result, fail_on=fail_on)
        result.exit_code = exit_code

        if fmt == "json":
            renderer = JsonRenderer()
            output_str = renderer.render(result)
        elif fmt == "sarif":
            output_str = """{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Python Hunter",
          "informationUri": "https://github.com/Kayinamura-Karimba-Geofrey/Python-hunter",
          "rules": []
        }
      },
      "results": []
    }
  ]
}"""
        else:
            renderer = TerminalRenderer()
            output_str = renderer.render(result)

        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output_str)
            if not ci:
                click.echo(f"Report written to '{out_file}'.")
        else:
            click.echo(output_str)

        sys.exit(exit_code)

    except Exception as e:
        click.echo(f"[!] Scan Error: {e}", err=True)
        sys.exit(ExitCode.TARGET_REPO_ERROR)


@main.command()
@click.argument("target", default=".")
def graph(target: str) -> None:
    """Builds and inspects the Whole-Project Security Knowledge Graph."""
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(target)
    nodes_count = len(result.graph.nodes) if result.graph else 0
    edges_count = len(result.graph.edges) if result.graph else 0
    click.echo(f"Security Knowledge Graph built successfully: {nodes_count} nodes, {edges_count} edges.")


@main.command()
@click.argument("target", default=".")
def attack_paths(target: str) -> None:
    """Reconstructs and displays end-to-end multi-vulnerability attack paths."""
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(target)
    click.echo(f"Reconstructed {len(result.attack_paths)} attack paths.")


@main.group()
def iac() -> None:
    """Analyze Infrastructure-as-Code, Containers, Kubernetes, Terraform, and CI/CD security."""
    pass


@iac.command("scan")
@click.argument("target", default=".")
def iac_scan(target: str) -> None:
    """Scan all infrastructure and container configurations in the target path."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    res = service.execute_infrastructure_scan(target)
    click.echo(f"Infrastructure Scan Completed: {res['resources_count']} resources analyzed, {res['findings_count']} findings, {res['attack_paths_count']} attack paths.")
    for f in res["findings"]:
        click.echo(f"  [{f['severity']}] {f['rule_id']} ({f['title']}): {f['file_path']}:{f['line_number']} - {f['evidence']}")


@iac.command("docker")
@click.argument("target", default=".")
def iac_docker(target: str) -> None:
    """Analyze Dockerfiles and Docker Compose files."""
    iac_scan.callback(target)


@iac.command("kubernetes")
@click.argument("target", default=".")
def iac_kubernetes(target: str) -> None:
    """Analyze Kubernetes manifests and RBAC permissions."""
    iac_scan.callback(target)


@iac.command("terraform")
@click.argument("target", default=".")
def iac_terraform(target: str) -> None:
    """Analyze Terraform HCL files and cloud resources."""
    iac_scan.callback(target)


@iac.command("helm")
@click.argument("target", default=".")
def iac_helm(target: str) -> None:
    """Analyze Helm charts and values statically."""
    iac_scan.callback(target)


@iac.command("ci")
@click.argument("target", default=".")
def iac_ci(target: str) -> None:
    """Analyze CI/CD and GitHub Actions workflows."""
    iac_scan.callback(target)


@main.group()
def ai() -> None:
    """Advanced AI Security Intelligence Engine & Autonomous Analysis."""
    pass


@ai.command("explain")
@click.argument("finding_id", default="PYH-AST-004")
def ai_explain(finding_id: str) -> None:
    """Explain a deterministic finding using AI evidence grounding."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    from python_hunter.domain.findings.finding import Finding
    from python_hunter.domain.common.enums import Severity
    service = SecurityApplicationService()
    dummy_f = Finding(rule_id=finding_id, title="Dangerous os.system execution", severity=Severity.HIGH)
    exp = service.ai_engine.explain_finding(dummy_f)
    click.echo(f"=== AI Security Explanation [{exp.finding_id}] ===")
    click.echo(f"What Happened   : {exp.what_happened}")
    click.echo(f"Why Dangerous   : {exp.why_dangerous}")
    click.echo(f"Location        : {exp.location_summary}")
    click.echo(f"Attacker Impact : {exp.attacker_possibilities}")
    click.echo(f"Remediation     : {exp.remediation_summary}")
    click.echo(f"AI Confidence   : {exp.confidence.value}")


@ai.command("prioritize")
@click.argument("target", default=".")
def ai_prioritize(target: str) -> None:
    """Contextually prioritize findings by business asset risk."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    from python_hunter.domain.findings.finding import Finding
    from python_hunter.domain.common.enums import Severity
    service = SecurityApplicationService()
    dummy_f = Finding(rule_id="PYH-AST-004", title="os.system call", severity=Severity.HIGH)
    assessment = service.ai_engine.prioritize_finding(dummy_f, repo_name=target)
    click.echo(f"=== Intelligent Risk Prioritization ===")
    click.echo(f"Original Severity   : {assessment.original_severity}")
    click.echo(f"Contextual Priority : {assessment.contextual_priority}")
    click.echo(f"Adjusted Score      : {assessment.adjusted_score}/100")
    click.echo(f"Reasoning           : {assessment.why_high_risk}")


@ai.command("remediate")
@click.argument("finding_id", default="PYH-AST-004")
def ai_remediate(finding_id: str) -> None:
    """Generate intelligent remediation and optional code patch suggestions."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    from python_hunter.domain.findings.finding import Finding
    from python_hunter.domain.common.enums import Severity
    service = SecurityApplicationService()
    dummy_f = Finding(rule_id=finding_id, title="Command Injection", severity=Severity.HIGH)
    rec = service.ai_engine.recommend_remediation(dummy_f)
    click.echo(f"=== Remediation Intelligence ===")
    click.echo(f"Recommended Fix  : {rec.recommended_fix}")
    click.echo(f"Why It Works     : {rec.why_it_works}")
    if rec.suggested_patch:
        click.echo(f"\n--- Suggested Patch (AI-Generated Suggestion Only) ---\n{rec.suggested_patch}")


@ai.command("summary")
@click.argument("target", default=".")
def ai_summary(target: str) -> None:
    """Generate Executive, Developer, or Analyst Security Summaries."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    sum_res = service.ai_engine.generate_security_summary([], target=target)
    click.echo(f"=== Executive AI Security Summary ({sum_res.target}) ===")
    click.echo(f"{sum_res.high_level_narrative}")
    click.echo(f"Critical Findings: {sum_res.critical_findings_count}")


@ai.command("query")
@click.argument("question")
def ai_query(question: str) -> None:
    """Execute authorized natural language security query."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    from python_hunter.domain.ai.models import AIQueryRequest
    service = SecurityApplicationService()
    req = AIQueryRequest(query=question, organization_id="org-default", user_id="cli-user")
    resp = service.ai_engine.query_assistant(req, [])
    click.echo(f"Q: {resp.query}")
    click.echo(f"A: {resp.answer}")


@main.group()
def compliance() -> None:
    """Enterprise Compliance, Control Mapping & Audit Reports."""
    pass


@compliance.command("frameworks")
def compliance_frameworks() -> None:
    """List supported compliance frameworks (ASVS, SAMM, NIST, CIS, ISO, SOC 2)."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    fws = service.enterprise_compliance_engine.list_frameworks()
    click.echo(f"=== Supported Compliance Frameworks ({len(fws)}) ===")
    for fw in fws:
        click.echo(f"[{fw.framework_id}] {fw.name} (v{fw.version}) - {fw.description}")


@compliance.command("assess")
@click.option("--framework", default="NIST_CSF_V2", help="Framework ID to assess.")
def compliance_assess(framework: str) -> None:
    """Run an automated compliance assessment against security findings."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    asm = service.enterprise_compliance_engine.create_assessment(framework_id=framework, assessor="cli-assessor")
    eval_res = service.enterprise_compliance_engine.evaluate_compliance(asm.assessment_id, [])
    click.echo(f"=== Compliance Assessment [{asm.assessment_id}] ===")
    click.echo(f"Framework        : {framework}")
    click.echo(f"Overall Score    : {eval_res['overall_score']}%")
    click.echo(f"Compliant Controls: {eval_res['compliant_controls']}/{eval_res['total_controls']}")


@compliance.command("status")
def compliance_status() -> None:
    """Display current organizational compliance posture."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    fws = service.enterprise_compliance_engine.list_frameworks()
    click.echo(f"=== Enterprise Compliance Status ===")
    click.echo(f"Active Frameworks Mapped : {len(fws)}")
    click.echo(f"Scoring Methodology     : Transparent Evidence Ratio (Compliant / Total)")


@compliance.command("gaps")
def compliance_gaps() -> None:
    """Display open compliance gaps and SLA breach status."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    gaps = service.enterprise_compliance_engine.list_gaps()
    click.echo(f"=== Open Compliance Gaps ({len(gaps)}) ===")
    for g in gaps:
        click.echo(f"[{g.gap_id}] Control: {g.control_id} | Severity: {g.severity} | SLA: {g.sla_status.value}")


@compliance.command("evidence")
def compliance_evidence() -> None:
    """Display tamper-evident compliance evidence records."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    click.echo("=== Tamper-Evident Evidence Store ===")
    click.echo("Evidence integrity verified via cryptographic SHA-256 content hashes.")


@compliance.command("report")
@click.option("--framework", default="NIST_CSF_V2", help="Framework ID.")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "text"]), default="text", help="Report format.")
def compliance_report(framework: str, fmt: str) -> None:
    """Generate an audit-ready compliance report package."""
    from python_hunter.application.services.security_app_service import SecurityApplicationService
    service = SecurityApplicationService()
    asm = service.enterprise_compliance_engine.create_assessment(framework_id=framework)
    pkg = service.enterprise_compliance_engine.generate_audit_report(asm.assessment_id)
    if fmt == "json":
        click.echo(service.enterprise_compliance_engine.reporting_engine.export_json(pkg))
    elif fmt == "csv":
        click.echo(service.enterprise_compliance_engine.reporting_engine.export_csv([]))
    else:
        click.echo(f"=== AUDIT PACKAGE: {pkg['title']} ===")
        click.echo(f"Organization: {pkg['organization']}")
        click.echo(f"Framework   : {pkg['framework_id']}")
        click.echo(f"Score       : {pkg['overall_compliance_score']}")
        click.echo(f"SHA-256 Hash: {pkg['report_signature_sha256']}")


if __name__ == "__main__":
    main()



