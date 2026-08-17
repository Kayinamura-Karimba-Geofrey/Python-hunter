"""CLI Secrets Command Handler."""

import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase


def run_secrets_command(args: list[str]) -> int:
    """Handle 'python-hunter secrets <path> [--format text|json]' command."""
    if not args or args[0] in ("-h", "--help"):
        print("Usage: python-hunter secrets <path> [--format text|json]")
        return 0

    target_path = args[0]
    output_format = "text"

    if "--format" in args:
        fmt_idx = args.index("--format")
        if fmt_idx + 1 < len(args):
            output_format = args[fmt_idx + 1].lower()

    use_case = AnalyzeSecretsUseCase()
    result = use_case.execute(target_path)

    if output_format == "json":
        _output_json(result)
    else:
        _output_text(result)

    return 0


def _output_text(result: dict[str, Any]) -> None:
    print(f"\n=== Python Hunter Secret Detection ===")
    print(f"Project Name:    {result['project_name']}")
    print(f"Files Scanned:   {result['files_scanned']}")
    print(f"Detectors Exec:  {result['detectors_executed']}")
    print(f"Total Findings:  {result['total_findings']}")
    print("──────────────────────────────────────────────────")

    for finding in result["findings"]:
        print(f"Detector ID: {finding.rule_id}")
        print(f"Severity:    {finding.severity}")
        print(f"Title:       {finding.title}")
        loc_str = f"{finding.file_path}:{finding.location.line_start}" if finding.location else finding.file_path
        print(f"File:        {loc_str}")
        print(f"Description: {finding.description}")
        print(f"Evidence:    {finding.evidence}")
        print("Remediation:")
        for rem_line in finding.remediation.splitlines():
            print(f"  {rem_line}")
        print("──────────────────────────────────────────────────\n")


def _output_json(result: dict[str, Any]) -> None:
    serializable_findings = []
    for f in result["findings"]:
        line = f.location.line_start if f.location else 1
        col = f.location.column_start if f.location else 0
        serializable_findings.append({
            "detector_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "category": f.category,
            "file_path": f.file_path,
            "line": line,
            "column": col,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "fingerprint": f.fingerprint,
        })

    json_output = {
        "project_name": result["project_name"],
        "files_scanned": result["files_scanned"],
        "detectors_executed": result["detectors_executed"],
        "total_findings": result["total_findings"],
        "findings": serializable_findings,
    }
    print(json.dumps(json_output, indent=2))
