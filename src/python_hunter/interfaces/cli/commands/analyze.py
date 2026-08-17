"""CLI Command handler for Security Analysis."""

import json
import sys
from typing import Any
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import RuleResult


def format_text_analysis(
    findings: list[Finding], ast_summary: ASTAnalysisSummary, rule_results: list[RuleResult]
) -> str:
    """Format security findings into clean human-readable text output."""
    lines: list[str] = []
    lines.append("\n=== Python Hunter Security Analysis ===")
    lines.append(f"Files Analyzed:  {ast_summary.files_analyzed}")
    lines.append(f"Rules Executed:  {len(rule_results)}")
    lines.append(f"Findings:        {len(findings)}")

    sev_counts = {s: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity] += 1

    lines.append("")
    for s in Severity:
        lines.append(f"{s.value:<12} {sev_counts[s]}")

    lines.append("\n" + "─" * 50 + "\n")

    if not findings:
        lines.append("No security vulnerabilities or weaknesses detected.\n")
    else:
        for f in findings:
            lines.append(f"Rule ID:     {f.rule_id}")
            lines.append(f"Severity:    {f.severity.value}")
            lines.append(f"Title:       {f.title}")
            lines.append(f"File:        {f.file_path}:{f.location.line_start}")
            lines.append(f"Confidence:  {f.confidence.value}")
            lines.append(f"Description: {f.description}")
            if f.evidence:
                lines.append(f"Evidence:    {f.evidence}")
            lines.append(f"Remediation: {f.remediation}")
            lines.append("\n" + "─" * 50 + "\n")

    return "\n".join(lines)


def format_json_analysis(
    findings: list[Finding], ast_summary: ASTAnalysisSummary, rule_results: list[RuleResult]
) -> str:
    """Format security analysis into structured JSON output."""
    data: dict[str, Any] = {
        "files_analyzed": ast_summary.files_analyzed,
        "rules_executed": len(rule_results),
        "total_findings": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "file_path": f.file_path,
                "line": f.location.line_start,
                "column": f.location.column_start,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2)


def run_analyze_command(target_path: str, output_format: str = "text") -> int:
    """Execute analyze CLI command."""
    try:
        use_case = AnalyzeSecurityUseCase()
        findings, ast_summary, rule_results = use_case.execute(target_path)

        if output_format.lower() == "json":
            sys.stdout.write(format_json_analysis(findings, ast_summary, rule_results) + "\n")
        else:
            sys.stdout.write(format_text_analysis(findings, ast_summary, rule_results) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"Error during security analysis: {e}\n")
        return 1
