"""CLI Subcommand for Safe Security Testing & Exploitability Verification."""

import argparse
import sys
from python_hunter.application.services.security_app_service import SecurityApplicationService


def register_verify_command(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("verify", help="Safely verify finding exploitability using passive evidence or controlled active testing")
    parser.add_argument("finding_id", nargs="?", default="find-01", help="Finding ID or target finding to verify")
    parser.add_argument("--passive", action="store_true", help="Perform static evidence verification without target execution (DEFAULT)")
    parser.add_argument("--active", action="store_true", help="Perform active non-destructive test against authorized local target")
    parser.add_argument("--authorized-target", help="Explicit authorized target URL or address (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--dry-run", action="store_true", help="Preview verification test plan without execution")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")


def handle_verify_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()

    if args.active and not args.authorized_target:
        sys.stderr.write("❌ ERROR: Active verification requires explicit target authorization.\n")
        sys.stderr.write("   Usage: python-hunter verify <finding_id> --active --authorized-target <http://localhost:8080>\n")
        sys.stderr.write("   Note : Default mode is PASSIVE. Never perform active testing on unauthorized targets.\n")
        return 1

    if args.authorized_target:
        service.authorize_verification_target(target=args.authorized_target, authorized_by="cli_operator")

    res = service.verify_finding(
        finding_id=args.finding_id,
        active=args.active,
        target=args.authorized_target,
        dry_run=args.dry_run,
    )

    if args.format == "json":
        import json
        sys.stdout.write(json.dumps(res, indent=2) + "\n")
        return 0

    sys.stdout.write("==========================================================\n")
    sys.stdout.write(" Python Hunter Safe Exploitability Verification\n")
    sys.stdout.write("==========================================================\n")
    sys.stdout.write(f"Finding ID          : {res['finding_id']}\n")
    sys.stdout.write(f"Verification Status : {res['verification_status']}\n")
    sys.stdout.write(f"Confidence Level    : {res['confidence']}\n")
    sys.stdout.write(f"Test Method         : {res['test_method']}\n")
    sys.stdout.write(f"Safety Level        : {res['safety_level']}\n")
    sys.stdout.write(f"Execution Time      : {res['execution_time_ms']:.2f} ms\n")
    sys.stdout.write(f"Tamper Proof Hash   : {res['test_hash'][:16]}...\n")
    sys.stdout.write("----------------------------------------------------------\n")
    sys.stdout.write(f"Evidence Summary    : {res['evidence']}\n")
    sys.stdout.write("==========================================================\n")

    return 0 if res["verification_status"] in ("VERIFIED", "LIKELY_EXPLOITABLE", "NOT_VERIFIED", "NOT_TESTED") else 1
