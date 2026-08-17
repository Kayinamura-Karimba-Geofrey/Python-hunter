"""CLI Subcommand for Vulnerability Intelligence Analysis."""

import argparse
import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_vulnerabilities import AnalyzeVulnerabilitiesUseCase
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import VulnerabilityMatch


def register_vulnerabilities_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register 'vulnerabilities' command into CLI argument parser."""
    parser = subparsers.add_parser(
        "vulnerabilities",
        help="Analyze third-party dependencies for known CVE/OSV security vulnerabilities.",
        description="Query vulnerability databases (OSV) and evaluate version ranges against dependencies.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to Python project repository or manifest directory.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Display detailed vulnerability findings, dependency paths, and remediation recommendations.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Operate strictly offline using local cached vulnerability records.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with non-zero status code if findings match or exceed specified severity threshold.",
    )


def run_vulnerabilities_command(args: list[str] | None = None) -> int:
    """Execute 'python-hunter vulnerabilities' subcommand."""
    parser = argparse.ArgumentParser(prog="python-hunter vulnerabilities")
    subparsers = parser.add_subparsers(dest="command")
    register_vulnerabilities_subcommand(subparsers)

    if args is None:
        args = sys.argv[1:]

    # Parse arguments
    if args and args[0] == "vulnerabilities":
        parsed_args = parser.parse_args(args)
    else:
        parsed_args = parser.parse_args(["vulnerabilities"] + args)

    use_case = AnalyzeVulnerabilitiesUseCase(offline=parsed_args.offline)
    result = use_case.execute(parsed_args.target)

    if parsed_args.format == "json":
        _output_json(result)
    else:
        _output_text(result, show_details=parsed_args.details)

    # Evaluate --fail-on exit code requirement
    if parsed_args.fail_on:
        threshold_sev = Severity[parsed_args.fail_on.upper()]
        findings: list[Finding] = result["findings"]
        for f in findings:
            if f.severity.weight >= threshold_sev.weight:
                return 1

    return 0


def _output_text(result: dict[str, Any], show_details: bool) -> None:
    """Format and print text summary to stdout."""
    inventory = result["inventory"]
    counts = result["status_counts"]
    findings: list[Finding] = result["findings"]
    matches: list[VulnerabilityMatch] = result["matches"]

    print("==========================================================")
    print(" Python Hunter Vulnerability Intelligence Analysis")
    print("==========================================================")
    print(f"Dependencies Analyzed : {inventory.total_count}")
    print(f"Vulnerability Database : {result['provider_name']}")
    print(f"Database Status       : {result['provider_status']}")
    print("----------------------------------------------------------")
    print("Vulnerability Assessment Summary:")
    print(f"  Confirmed Vulnerable : {counts['AFFECTED']}")
    print(f"  Potentially Affected : {counts['POTENTIALLY_AFFECTED']}")
    print(f"  Not Affected         : {counts['NOT_AFFECTED']}")
    print(f"  Unknown Version      : {counts['UNKNOWN']}")
    print(f"  Withdrawn Advisories : {counts['WITHDRAWN']}")
    print("==========================================================")

    if findings:
        print(f"\n[!] Identified {len(findings)} Vulnerability Findings:")
        for idx, f in enumerate(findings, start=1):
            print(f"\n{idx}. [{f.severity.value}] {f.rule_id}: {f.title}")
            print(f"   Manifest : {f.file_path}")
            print(f"   Details  : {f.description}")
            if show_details:
                print(f"   Evidence : {f.evidence}")
                print(f"   Fix      : {f.remediation}")
    else:
        print("\n[+] No vulnerable dependencies identified.")


def _output_json(result: dict[str, Any]) -> None:
    """Format and print JSON representation to stdout."""
    inventory = result["inventory"]
    findings: list[Finding] = result["findings"]
    matches: list[VulnerabilityMatch] = result["matches"]

    out = {
        "summary": {
            "dependencies_count": inventory.total_count,
            "provider_name": result["provider_name"],
            "provider_status": result["provider_status"],
            "status_counts": result["status_counts"],
            "findings_count": len(findings),
        },
        "matches": [
            {
                "package": m.dependency.name,
                "installed_version": m.dependency.version,
                "status": m.status.value,
                "vulnerability_id": m.vulnerability.id,
                "summary": m.vulnerability.summary,
                "severity": m.vulnerability.severity.value,
                "recommended_fix": m.recommended_fix,
                "dependency_paths": m.dependency_paths,
            }
            for m in matches
        ],
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    print(json.dumps(out, indent=2))
