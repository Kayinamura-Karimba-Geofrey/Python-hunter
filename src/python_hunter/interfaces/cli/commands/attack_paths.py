"""Attack Paths CLI Subcommand."""

import argparse
import sys
from typing import List

from python_hunter.application.services.security_app_service import SecurityApplicationService


def register_attack_paths_command(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("attack-paths", help="Visualize and analyze cross-domain evidence-backed attack paths")
    parser.add_argument("target", nargs="?", default=".", help="Target path to analyze")
    parser.add_argument("--critical", action="store_true", help="Filter for critical attack paths only")
    parser.add_argument("--entry-point", help="Filter attack paths by entry point ID or route")
    parser.add_argument("--asset", help="Filter attack paths by target asset ID or database")
    parser.add_argument("--explain", help="Explain attack path step-by-step by ID")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")


def handle_attack_paths_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    
    if getattr(args, "explain", None):
        paths = service.list_attack_paths()
        target_path = next((p for p in paths if p["id"] == args.explain), paths[0])
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(f" Attack Path Explanation: {target_path['id']}\n")
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(f"Title            : {target_path['title']}\n")
        sys.stdout.write(f"Risk Score       : {target_path['risk_score']}/100\n")
        sys.stdout.write(f"Entry Point      : {target_path.get('entry_point', '/api')}\n")
        sys.stdout.write(f"Target Asset     : {target_path.get('target_asset', 'Database')}\n")
        sys.stdout.write(f"Remediation      : {target_path.get('remediation', 'N/A')}\n")
        sys.stdout.write("----------------------------------------------------------\n")
        sys.stdout.write("Path Progression Nodes:\n")
        for idx, node in enumerate(target_path.get("nodes", []), 1):
            sys.stdout.write(f"  {idx}. [{node['type'].upper()}] {node['label']} (Risk: {node['risk_score']})\n")
        sys.stdout.write("==========================================================\n")
        return 0

    paths = service.list_attack_paths()
    if args.critical:
        paths = [p for p in paths if p.get("risk_score", 0) >= 80.0]

    if args.format == "json":
        import json
        sys.stdout.write(json.dumps(paths, indent=2) + "\n")
        return 0

    sys.stdout.write("==========================================================\n")
    sys.stdout.write(" Python Hunter Correlated Attack-Path Intelligence\n")
    sys.stdout.write("==========================================================\n")
    sys.stdout.write(f"Total Attack Paths Discovered: {len(paths)}\n")
    sys.stdout.write("==========================================================\n\n")

    for p in paths:
        sys.stdout.write(f"[!] ATTACK PATH: {p['id']} — {p['title']}\n")
        sys.stdout.write(f"    Risk Score  : {p['risk_score']} / 100 [{p.get('confidence', 'HIGH')}]\n")
        sys.stdout.write(f"    Entry Point : {p.get('entry_point', 'Internet')}\n")
        sys.stdout.write(f"    Target Asset: {p.get('target_asset', 'Cloud DB')}\n")
        sys.stdout.write(f"    Remediation : {p.get('remediation', 'See dashboard')}\n")
        sys.stdout.write("----------------------------------------------------------\n")

    return 0
