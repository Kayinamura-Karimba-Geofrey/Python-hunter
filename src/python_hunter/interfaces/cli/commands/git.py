"""CLI Subcommand for Git Repository & History Security Analysis."""

import argparse
import json
import sys
from typing import Any

from python_hunter.application.use_cases.analyze_git import AnalyzeGitUseCase
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.git.models import SecretLifecycleStatus


def register_git_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register 'git' subcommand in CLI argument parser."""
    parser = subparsers.add_parser(
        "git",
        help="Analyze Git repository history and metadata for security risks.",
        description="Inspect Git commits, historical secrets, sensitive files, .gitignore omissions, remotes, and hooks.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project or repository path (default: current directory).",
    )
    parser.add_argument(
        "--commits",
        type=int,
        default=500,
        help="Maximum number of historical commits to analyze (default: 500).",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="Filter commits since date (ISO format or Git date e.g. 2026-01-01).",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Filter commit history by specific file or subdirectory path.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Display detailed secret lifecycle and finding breakdown.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: text (default) or json.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with non-zero code if findings meet or exceed severity threshold.",
    )


def run_git_command(args: argparse.Namespace) -> int:
    """Execute 'git' subcommand logic and return exit code."""
    use_case = AnalyzeGitUseCase()
    res = use_case.execute(
        target_path=args.target,
        max_commits=args.commits,
        since=args.since,
        path_filter=args.path,
    )

    if not res.get("is_git_repository"):
        if args.format == "json":
            print(json.dumps({"error": f"Path '{args.target}' is not a valid Git repository."}, indent=2))
        else:
            print(f"[-] Error: Path '{args.target}' is not a valid Git repository.")
        return 1

    if args.format == "json":
        return _render_json(res)
    else:
        return _render_text(res, details=args.details, fail_on=args.fail_on)


def _render_text(res: dict[str, Any], details: bool, fail_on: str | None) -> int:
    meta = res["metadata"]
    summary = res["summary_counts"]
    findings: list[Finding] = res["findings"]
    records = res["secret_records"]

    print("==========================================================")
    print(" Python Hunter Git Repository Security Analysis")
    print("==========================================================")
    print(f"Repository Root    : {res['repository_root']}")
    print(f"HEAD Commit        : {meta.head_commit[:8] if meta and meta.head_commit else 'N/A'}")
    print(f"Branch             : {meta.default_branch if meta else 'N/A'}")
    print(f"Commits Analyzed   : {res['commits_analyzed']}")
    print(f"Completeness       : {meta.completeness.value if meta else 'UNKNOWN'}")
    print("----------------------------------------------------------")
    print("Git Security Analysis Summary:")
    print(f"  Historical Secrets Found  : {summary['total_historical_secrets']}")
    print(f"  Secrets Still Present     : {summary['secrets_still_present']}")
    print(f"  Secrets Removed from HEAD : {summary['secrets_removed']}")
    print(f"  Total Git Security Risks  : {summary['git_findings_count']}")
    print("==========================================================")

    if details and records:
        print("\n--- Historical Secret Lifecycles ---")
        for rec in records:
            status = "REMOVED" if rec.current_status == SecretLifecycleStatus.REMOVED_FROM_HEAD else "STILL PRESENT"
            exp = f" ({rec.exposure_days} days exposure)" if rec.exposure_days > 0 else ""
            print(f"  [{status}] {rec.file_path} (Introduced: {rec.introduced_commit[:8]}){exp}")

    if findings:
        print(f"\n[!] Detected {len(findings)} Git security findings:")
        for f in findings:
            print(f"\n  [{f.severity.value}] {f.rule_id}: {f.title}")
            print(f"      File     : {f.file_path}")
            print(f"      Evidence : {f.evidence}")
            if details:
                print(f"      Details  : {f.description}")
                print(f"      Remediation:\n        {f.remediation.replace(chr(10), chr(10) + '        ')}")
    else:
        print("\n[+] No Git security vulnerabilities or secret leaks identified.")

    return _evaluate_exit_code(findings, fail_on)


def _render_json(res: dict[str, Any]) -> int:
    meta = res["metadata"]
    findings: list[Finding] = res["findings"]
    records = res["secret_records"]

    out = {
        "repository_root": res["repository_root"],
        "commits_analyzed": res["commits_analyzed"],
        "metadata": {
            "head_commit": meta.head_commit if meta else "",
            "default_branch": meta.default_branch if meta else "",
            "branches": meta.branches if meta else [],
            "tags": meta.tags if meta else [],
            "total_commits": meta.total_commits if meta else 0,
            "is_shallow": meta.is_shallow if meta else False,
            "completeness": meta.completeness.value if meta else "UNKNOWN",
        } if meta else None,
        "summary": res.get("summary_counts", {}),
        "secret_lifecycles": [
            {
                "secret_fingerprint": r.secret_fingerprint,
                "secret_type": r.secret_type,
                "file_path": r.file_path,
                "introduced_commit": r.introduced_commit,
                "removed_commit": r.removed_commit,
                "current_status": r.current_status.value,
                "exposure_days": r.exposure_days,
            }
            for r in records
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
