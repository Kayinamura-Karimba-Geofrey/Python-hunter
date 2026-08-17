"""CLI Subcommand for Call Graph & Control-Flow Analysis."""

import argparse
import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_callgraph import AnalyzeCallGraphUseCase
from python_hunter.domain.callgraph.models import CallEdge, EntryPoint, Symbol
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding


def register_callgraph_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register 'callgraph' subcommand in CLI argument parser."""
    parser = subparsers.add_parser(
        "callgraph",
        help="Build interprocedural call graph, symbol table, CFG, and entry point reachability.",
        description="Analyze call site resolution, module import dependencies, control-flow graphs, and security sink reachability.",
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
        help="Display detailed symbol catalog, import dependencies, and entry point call paths.",
    )
    parser.add_argument(
        "--function",
        type=str,
        default=None,
        help="Filter call graph analysis to specific qualified function name.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "dot"],
        default="text",
        help="Output display format: text (default), json, or dot (Graphviz).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with non-zero status if findings meet or exceed severity threshold.",
    )


def run_callgraph_command(args: argparse.Namespace) -> int:
    """Execute 'callgraph' subcommand logic and return exit code."""
    use_case = AnalyzeCallGraphUseCase()
    res = use_case.execute(target_path=args.target, function_filter=args.function)

    if args.format == "dot":
        print(res["dot_output"])
        return 0
    elif args.format == "json":
        return _render_json(res)
    else:
        return _render_text(res, details=args.details, fail_on=args.fail_on)


def _render_text(res: dict[str, Any], details: bool, fail_on: str | None) -> int:
    symbols: dict[str, Symbol] = res["symbols"]
    call_edges: list[CallEdge] = res["call_edges"]
    entry_points: list[EntryPoint] = res["entry_points"]
    findings: list[Finding] = res["findings"]

    print("==========================================================")
    print(" Python Hunter Interprocedural Call Graph & CFG Engine")
    print("==========================================================")
    print(f"Target Path            : {res['target_path']}")
    print(f"Indexed Symbols        : {len(symbols)}")
    print(f"Import Edges           : {len(res['imports'])}")
    print(f"Discovered Call Edges  : {len(call_edges)}")
    print(f"Application Entry Points: {len(entry_points)}")
    print(f"Recursion Cycles (SCC): {len(res['sccs'])}")
    print(f"Call Graph Findings    : {len(findings)}")
    print("==========================================================")

    if details or True:
        print("\n--- Discovered Application Entry Points ---")
        for ep in entry_points:
            print(f"  • [{ep.entry_type.value}] {ep.qualified_name} ({ep.file_path})")

        print("\n--- Interprocedural Call Graph Edges ---")
        for edge in call_edges[:15]:
            print(f"  {edge.caller_qualified_name} -> {edge.callee_qualified_name} [{edge.edge_type.value}]")
        if len(call_edges) > 15:
            print(f"  ... and {len(call_edges) - 15} more edges.")

    if findings:
        print(f"\n[!] Discovered {len(findings)} Call Graph Security Risks:")
        for f in findings:
            print(f"  • [{f.severity.value}] {f.rule_id}: {f.title}")

    return _evaluate_exit_code(findings, fail_on)


def _render_json(res: dict[str, Any]) -> int:
    symbols: dict[str, Symbol] = res["symbols"]
    call_edges: list[CallEdge] = res["call_edges"]
    entry_points: list[EntryPoint] = res["entry_points"]
    findings: list[Finding] = res["findings"]

    out = {
        "target_path": res["target_path"],
        "symbols_count": len(symbols),
        "symbols": [
            {"qualified_name": q, "type": s.symbol_type.value, "file": s.file_path}
            for q, s in symbols.items()
        ],
        "call_edges": [
            {
                "caller": e.caller_qualified_name,
                "callee": e.callee_qualified_name,
                "type": e.edge_type.value,
                "confidence": e.confidence.value,
            }
            for e in call_edges
        ],
        "entry_points": [
            {
                "name": ep.name,
                "qualified_name": ep.qualified_name,
                "type": ep.entry_type.value,
                "file": ep.file_path,
            }
            for ep in entry_points
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
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
