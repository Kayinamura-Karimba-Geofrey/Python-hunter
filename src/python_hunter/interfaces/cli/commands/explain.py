"""CLI Explain Command for Security Dataflow Evidence and Exploitability Proofs."""

import argparse
import sys
from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase


def run_explain_command(args: argparse.Namespace) -> int:
    """Execute finding explain command showing step-by-step source-to-sink proof."""
    target_path = getattr(args, "target", ".")
    finding_id = getattr(args, "finding_id", None)

    use_case = AnalyzeTaintUseCase()
    result = use_case.execute(target_path)
    flows = result.get("flows", [])

    if not flows:
        print("No security dataflow paths discovered in target path.")
        return 0

    print("==========================================================")
    print(" Python Hunter Dataflow Evidence & Exploitability Proofs ")
    print("==========================================================")

    matched = 0
    for flow in flows:
        if flow.proof:
            if finding_id is None or finding_id in flow.proof.sink_description or finding_id in flow.vulnerability_type:
                print(flow.proof.explain())
                print("-" * 58)
                matched += 1

    if matched == 0:
        print(f"No dataflow proof matched finding ID '{finding_id}'. Showing first available proof:")
        if flows[0].proof:
            print(flows[0].proof.explain())

    return 0
