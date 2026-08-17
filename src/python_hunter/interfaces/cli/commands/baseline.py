"""CLI subcommand: baseline and diff."""

import argparse
import json
import sys

from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.baseline.engine import BaselineEngine


def run_baseline_command(args: argparse.Namespace) -> int:
    """Create baseline snapshot file for target project."""
    use_case = AnalyzeSecurityUseCase()
    try:
        findings, _, _ = use_case.execute(args.target)
    except Exception as e:
        print(f"Analysis Error: {e}", file=sys.stderr)
        return 2

    output_file = args.output or "pyh_baseline.json"
    data = BaselineEngine.create_baseline(findings, output_file)

    print("==========================================================")
    print(" Python Hunter Baseline Snapshot Engine")
    print("==========================================================")
    print(f"Target Path            : {args.target}")
    print(f"Baseline Output File   : {output_file}")
    print(f"Captured Findings      : {data['count']}")
    print("==========================================================")
    return 0


def run_diff_command(args: argparse.Namespace) -> int:
    """Compare two scan JSON output files."""
    try:
        with open(args.old_scan, "r", encoding="utf-8") as f:
            old_data = json.load(f)
        with open(args.new_scan, "r", encoding="utf-8") as f:
            new_data = json.load(f)
    except Exception as e:
        print(f"Error loading scan JSON files: {e}", file=sys.stderr)
        return 3

    diff = BaselineEngine.diff_scans(old_data, new_data)

    print("==========================================================")
    print(" Python Hunter Security Scan Diff Engine")
    print("==========================================================")
    print(f"Old Scan File          : {args.old_scan}")
    print(f"New Scan File          : {args.new_scan}")
    print(f"Added Findings         : +{diff['added_count']}")
    print(f"Removed Findings       : -{diff['removed_count']}")
    print(f"Unchanged Findings     :  {diff['unchanged_count']}")
    print("==========================================================")
    return 0
