"""CLI Command handler for Security Analysis."""

import json
import sys
from typing import Any
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import RuleResult


from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.policy.engine import SecurityPolicyEngine
from python_hunter.infrastructure.reporting.sarif_exporter import SARIFExporter


def format_text_analysis(
    findings: list[Finding], ast_summary: ASTAnalysisSummary, rule_results: list[RuleResult], target_path: str = "."
) -> str:
    """Format security findings into clean human-readable text output."""
    correlator = FindingCorrelator()
    deduped, attack_paths = correlator.correlate(findings)

    risk_engine = RiskEngine()
    risk_engine.score_findings(deduped)
    posture = risk_engine.calculate_posture(deduped, attack_paths)

    policy_engine = SecurityPolicyEngine.from_config_file(f"{target_path}/pyh_policy.yml")
    passed, violations = policy_engine.evaluate(deduped, posture.project_risk_score)
    posture.policy_passed = passed
    posture.policy_violations = violations

    lines: list[str] = []
    lines.append("\n==========================================================")
    lines.append(" Python Hunter Security & Risk Intelligence Analysis")
    lines.append("==========================================================")
    lines.append(f"Target Path            : {target_path}")
    print_files = getattr(ast_summary, "files_analyzed", len(getattr(ast_summary, "documents", [])))
    lines.append(f"Files Analyzed         : {print_files}")
    lines.append(f"Overall Project Risk   : {posture.project_risk_score}/100")
    lines.append(f"Security Gate Result   : {'PASSED' if passed else 'FAILED'}")
    lines.append(f"Total Unique Findings  : {posture.total_findings}")
    lines.append(f"Correlated Attack Paths: {posture.attack_path_count}")
    lines.append("==========================================================")

    lines.append("\n--- Findings Severity Summary ---")
    lines.append(f"  Critical : {posture.critical_count}")
    lines.append(f"  High     : {posture.high_count}")
    lines.append(f"  Medium   : {posture.medium_count}")
    lines.append(f"  Low      : {posture.low_count}")
    lines.append(f"  Info     : {posture.info_count}")

    if attack_paths:
        lines.append("\n--- Correlated Attack Paths ---")
        for ap in attack_paths:
            lines.append(f"  • [{ap.attack_type.value}] {ap.title} (Risk Score: {ap.risk_score})")

    lines.append("\n" + "─" * 58 + "\n")

    if not deduped:
        lines.append("No security vulnerabilities or weaknesses detected.\n")
    else:
        for f in deduped:
            lines.append(f"Rule ID:     {f.rule_id}")
            lines.append(f"Severity:    {f.severity.value} | Risk Score: {f.risk_score}")
            lines.append(f"Confidence:  {f.confidence.value} | Exposure: {f.exposure.value}")
            lines.append(f"Title:       {f.title}")
            line_no = f.location.line_start if f.location else 0
            lines.append(f"File:        {f.file_path}:{line_no}")
            lines.append(f"Description: {f.description}")
            if f.evidence:
                lines.append(f"Evidence:    {f.evidence}")
            if f.secondary_evidence:
                lines.append(f"Correlated : {'; '.join(f.secondary_evidence)}")
            lines.append(f"Remediation: {f.remediation}")
            lines.append("\n" + "─" * 58 + "\n")

    return "\n".join(lines)


def format_json_analysis(
    findings: list[Finding], ast_summary: ASTAnalysisSummary, rule_results: list[RuleResult], target_path: str = "."
) -> str:
    """Format security analysis into structured JSON output."""
    correlator = FindingCorrelator()
    deduped, attack_paths = correlator.correlate(findings)

    risk_engine = RiskEngine()
    risk_engine.score_findings(deduped)
    posture = risk_engine.calculate_posture(deduped, attack_paths)

    policy_engine = SecurityPolicyEngine.from_config_file(f"{target_path}/pyh_policy.yml")
    passed, violations = policy_engine.evaluate(deduped, posture.project_risk_score)

    print_files = getattr(ast_summary, "files_analyzed", len(getattr(ast_summary, "documents", [])))

    data: dict[str, Any] = {
        "target_path": target_path,
        "files_analyzed": print_files,
        "total_findings": len(deduped),
        "project_risk_score": posture.project_risk_score,
        "policy_passed": passed,
        "policy_violations": violations,
        "attack_paths": [
            {
                "id": ap.id,
                "type": ap.attack_type.value,
                "title": ap.title,
                "entry_point": ap.entry_point,
                "target_sink": ap.target_sink,
                "risk_score": ap.risk_score,
            }
            for ap in attack_paths
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "risk_score": f.risk_score,
                "exposure": f.exposure.value,
                "reachability": f.reachability.value,
                "lifecycle_state": f.lifecycle_state.value,
                "file_path": f.file_path,
                "line": f.location.line_start if f.location else 0,
                "description": f.description,
                "evidence": f.evidence,
                "secondary_evidence": f.secondary_evidence,
                "remediation": f.remediation,
                "fingerprint": f.fingerprint,
                "risk_explanation": f.metadata.get("risk_explanation", {}),
            }
            for f in deduped
        ],
    }
    return json.dumps(data, indent=2)


def run_analyze_command(target_path: str, output_format: str = "text") -> int:
    """Execute analyze CLI command."""
    try:
        use_case = AnalyzeSecurityUseCase()
        findings, ast_summary, rule_results = use_case.execute(target_path)

        fmt = output_format.lower()
        if fmt == "json":
            sys.stdout.write(format_json_analysis(findings, ast_summary, rule_results, target_path) + "\n")
        elif fmt == "sarif":
            sys.stdout.write(SARIFExporter.export_json(findings) + "\n")
        else:
            sys.stdout.write(format_text_analysis(findings, ast_summary, rule_results, target_path) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"Error during security analysis: {e}\n")
        return 1

