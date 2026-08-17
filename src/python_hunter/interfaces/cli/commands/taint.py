"""CLI Subcommand for Static Dataflow & Taint Analysis."""

import argparse
import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.taint.models import TaintFlow


def register_taint_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register 'taint' subcommand in CLI argument parser."""
    parser = subparsers.add_parser(
        "taint",
        help="Execute static dataflow and taint propagation analysis.",
        description="Track untrusted dataflow from sources (HTTP, CLI, env, files, DB) to dangerous sinks.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or Python source file (default: current directory).",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Display detailed source-to-sink flow paths and remediation steps.",
    )
    parser.add_argument(
        "--rule",
        type=str,
        default=None,
        help="Filter analysis findings by rule ID (e.g. PYH-TAINT-SQL-001).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output display format: text (default) or json.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with non-zero status if findings meet or exceed severity threshold.",
    )


def run_taint_command(args: argparse.Namespace) -> int:
    """Execute 'taint' subcommand logic and return exit code."""
    use_case = AnalyzeTaintUseCase()
    res = use_case.execute(target_path=args.target, rule_filter=args.rule)

    if args.format == "json":
        return _render_json(res)
    else:
        return _render_text(res, details=args.details, fail_on=args.fail_on)


def _render_text(res: dict[str, Any], details: bool, fail_on: str | None) -> int:
    summary = res["summary_counts"]
    findings: list[Finding] = res["findings"]
    flows: list[TaintFlow] = res["flows"]

    print("==========================================================")
    print(" Python Hunter Static Dataflow & Taint Analysis")
    print("==========================================================")
    print(f"Target Path            : {res['target_path']}")
    print(f"Files Analyzed         : {summary['files_analyzed']}")
    print(f"Flow Paths Discovered  : {summary['total_flows_discovered']}")
    print(f"Taint Security Risks   : {summary['taint_findings_count']}")
    print("==========================================================")

    if findings:
        print(f"\n[!] Discovered {len(findings)} dataflow vulnerabilities:")
        for idx, (f, flow) in enumerate(zip(findings, flows), start=1):
            print(f"\n--- Flow #{idx} [{f.severity.value}] {f.rule_id}: {f.title} ---")
            print(f"File     : {f.file_path}:{f.location.line_start if f.location else '1'}")
            print(f"Source   : {flow.source_node.label} ({flow.source_category.value})")
            print(f"Sink     : {flow.sink_node.label} ({flow.sink_category.value})")

            if details or True:
                print("\n  Dataflow Propagation Path:")
                for node in flow.flow_path:
                    loc_str = f" ({node.location.to_string()})" if node.location else ""
                    print(f"    ↓ [{node.node_type.upper()}] {node.label}{loc_str}")

            if details:
                print(f"\n  Remediation:\n    {f.remediation.replace(chr(10), chr(10) + '    ')}")
    else:
        print("\n[+] No un-sanitized dangerous dataflow paths detected.")

    return _evaluate_exit_code(findings, fail_on)


def _render_json(res: dict[str, Any]) -> int:
    summary = res["summary_counts"]
    findings: list[Finding] = res["findings"]
    flows: list[TaintFlow] = res["flows"]

    out = {
        "target_path": res["target_path"],
        "summary": summary,
        "flows": [
            {
                "source": flow.source_node.label,
                "source_category": flow.source_category.value,
                "sink": flow.sink_node.label,
                "sink_category": flow.sink_category.value,
                "vulnerability_type": flow.vulnerability_type,
                "severity": flow.severity.value,
                "confidence": flow.confidence.value,
                "is_sanitized": flow.is_sanitized,
                "path": [
                    {
                        "label": node.label,
                        "type": node.node_type,
                        "location": node.location.to_string() if node.location else None,
                    }
                    for node in flow.flow_path
                ],
            }
            for flow in flows
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "evidence": f.evidence,
                "fingerprint": f.fingerprint,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }

    print(json.dumps(out, indent=2))
    return 0


def _evaluate_exit_code(findings: list[Finding], fail_on: str | None) -> int:
    if not fail_on or not findings:
        return 0

    threshold_severity = Severity[fail_on.upper()]
    for f in findings:
        if f.severity.weight >= threshold_severity.weight:
            return 1
    return 0
