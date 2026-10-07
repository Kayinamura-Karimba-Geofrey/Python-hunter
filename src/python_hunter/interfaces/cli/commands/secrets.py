"""CLI Secrets Command Handler."""

import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_secrets import AnalyzeSecretsUseCase


def _emit(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def run_secrets_command(args: list[str]) -> int:
    """Handle 'python-hunter secrets <path> [--format text|json]' command."""
    if not args or args[0] in ("-h", "--help"):
        _emit("Usage: python-hunter secrets <path> [--format text|json]")
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
    _emit("\n=== Python Hunter Secret Detection ===")
    _emit(f"Project Name:    {result['project_name']}")
    _emit(f"Files Scanned:   {result['files_scanned']}")
    _emit(f"Detectors Exec:  {result['detectors_executed']}")
    _emit(f"Total Findings:  {result['total_findings']}")
    _emit("──────────────────────────────────────────────────")

    for finding in result["findings"]:
        _emit(f"Detector ID: {finding.rule_id}")
        _emit(f"Severity:    {finding.severity}")
        _emit(f"Title:       {finding.title}")
        loc_str = f"{finding.file_path}:{finding.location.line_start}" if finding.location else finding.file_path
        _emit(f"File:        {loc_str}")
        _emit(f"Description: {finding.description}")
        _emit(f"Evidence:    {finding.evidence}")
        _emit("Remediation:")
        for rem_line in finding.remediation.splitlines():
            _emit(f"  {rem_line}")
        _emit("──────────────────────────────────────────────────\n")


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
    _emit(json.dumps(json_output, indent=2))


def run_workspace_secrets_command(target: str, output_format: str) -> int:
    """Handle the top-level 'secrets' CLI command: workspace plus Git history exposure scan."""
    from python_hunter.application.services.workspace_scans import execute_secrets_scan

    scan_res = execute_secrets_scan(target, scan_history=True)
    if output_format == "json":
        sys.stdout.write(json.dumps(scan_res, indent=2) + "\n")
    else:
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(" Python Hunter Credential Exposure Intelligence\n")
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(f"Target Path            : {scan_res['workspace_path']}\n")
        sys.stdout.write(f"Active Exposures       : {scan_res['active_secrets_count']}\n")
        sys.stdout.write(f"Historical Exposures   : {scan_res['historical_secrets_count']}\n")
        sys.stdout.write("==========================================================\n\n")

        for s in scan_res["active_secrets"]:
            sys.stdout.write(f"[!] {s['severity']} SECRET DETECTED ({s['rule_id']})\n")
            sys.stdout.write(f"    Title       : {s['title']}\n")
            sys.stdout.write(f"    File/Line   : {s['file_path']}:{s['line']}\n")
            sys.stdout.write(f"    Fingerprint : {s['fingerprint']}\n")
            sys.stdout.write(f"    Evidence    : {s['evidence']}\n")
            sys.stdout.write("----------------------------------------------------------\n")
    return 0 if scan_res["active_secrets_count"] == 0 else 1
