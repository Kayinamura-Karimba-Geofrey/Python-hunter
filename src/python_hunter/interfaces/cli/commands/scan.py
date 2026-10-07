"""CLI command for the full security scan pipeline."""

import argparse
import sys
import uuid
from datetime import UTC, datetime

from python_hunter.application.orchestrator.scan_context import ScanResult


def register_scan_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'scan' command."""
    scan_parser = subparsers.add_parser("scan", help="Execute security scan on target directory or repository")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan (local directory or remote git URL)")
    scan_parser.add_argument("--branch", default="", help="Git branch to clone/scan")
    scan_parser.add_argument("--commit", default="", help="Specific Git commit SHA to checkout and scan")
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "markdown", "md", "html", "csv", "cyclonedx", "cdx", "spdx", "spdx-json"],
        default="terminal",
        help="Output format (terminal, json, sarif, markdown, html, csv, cyclonedx, spdx)",
    )
    scan_parser.add_argument("-o", "--output", help="Output file path")
    scan_parser.add_argument(
        "--fail-on", default="high", help="Severity threshold to trigger non-zero exit code (critical, high, medium, low)"
    )
    scan_parser.add_argument("--ci", action="store_true", help="Enable CI-friendly execution mode")
    scan_parser.add_argument("--clean", action="store_true", help="Automatically remediate/clean detected malware threats (e.g. PolinRider)")
    scan_parser.add_argument("--language", action="append", help="Target language filter (e.g. java, go, rust)")
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Wall-clock timeout in seconds for repository clone (default: no wall-clock limit when active)",
    )
    scan_parser.add_argument(
        "--idle-timeout",
        type=int,
        default=None,
        help="Inactivity timeout in seconds before aborting stalled git clone (default: 45s)",
    )
    scan_parser.add_argument("--no-secrets", action="store_true", help="Disable secret scanning during security scan")
    scan_parser.add_argument(
        "--no-dependencies", "--no-sca", dest="no_dependencies", action="store_true", help="Disable SCA dependency and vulnerability scanning"
    )
    scan_parser.add_argument("--offline", action="store_true", help="Operate strictly offline without querying remote vulnerability databases")
    scan_parser.add_argument(
        "--no-record", action="store_true", help="Do not save this scan to the local scan history (PYH_DATA_DIR)"
    )


def run_scan_command(args: argparse.Namespace) -> int:
    from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
    from python_hunter.presentation.policy import PolicyEngine
    from python_hunter.presentation.renderer import get_renderer

    created_at = datetime.now(UTC).isoformat()
    opts = {
        "ci": args.ci,
        "clean": args.clean,
        "language": args.language,
        "framework": getattr(args, "framework", None),
        "timeout": args.timeout,
        "idle_timeout": args.idle_timeout,
        "no_secrets": args.no_secrets,
        "no_dependencies": args.no_dependencies,
        "offline": args.offline,
    }
    try:
        res = ScanOrchestrator().run_scan(
            target_str=args.target,
            branch=args.branch,
            commit=args.commit,
            tag=getattr(args, "tag", ""),
            fail_on=args.fail_on,
            options=opts,
        )
    except Exception as e:
        sys.stderr.write(f"Error during scan: {e}\n")
        return 1

    res.exit_code = int(PolicyEngine().evaluate(res, fail_on=args.fail_on))

    if not args.no_record:
        _record_scan(args.target, res, created_at)

    output_str = get_renderer(args.format).render(res)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str + "\n")
    else:
        sys.stdout.write(output_str + "\n")

    return res.exit_code


def _record_scan(target: str, res: ScanResult, created_at: str) -> None:
    """Persist the scan so the API and dashboard can report on it. Never fails the scan."""
    from python_hunter.application.services.scan_queries import build_scan_record
    from python_hunter.domain.policy.policy_evaluator import PolicyEngine as GatePolicyEngine
    from python_hunter.infrastructure.storage.scan_store import ScanResultStore

    try:
        risk_score = float(res.project_risk.overall_score) if res.project_risk else 0.0
        gate = GatePolicyEngine().evaluate_gate(res.findings, risk_score=risk_score)
        store = ScanResultStore()
        record = build_scan_record(str(uuid.uuid4()), target, "strict", res, gate, created_at)
        store.save_scan(record)
        store.append_audit("SCAN_EXECUTED", "cli", target, "SUCCESS")
    except Exception as e:
        sys.stderr.write(f"Warning: scan completed but could not be recorded: {e}\n")
