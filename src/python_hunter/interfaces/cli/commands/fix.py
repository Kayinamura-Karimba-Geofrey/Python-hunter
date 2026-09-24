"""CLI Command Handler for Automated Dependency Fixes and Version Bumping."""

import argparse
import json
import sys

from python_hunter.application.use_cases.fix_dependencies import FixDependenciesUseCase


def run_fix_command(args: list[str]) -> int:
    """Execute python-hunter fix command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter fix",
        description="Automatically update vulnerable, unpinned, and policy-violating dependency versions.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or repository (default: .)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview proposed dependency updates without writing changes to disk",
    )
    parser.add_argument(
        "--unpinned-only",
        action="store_true",
        help="Only pin unconstrained or broad dependencies",
    )
    parser.add_argument(
        "--vulns-only",
        action="store_true",
        help="Only fix dependencies matching known vulnerability advisories",
    )
    parser.add_argument(
        "--create-pr",
        action="store_true",
        help="Commit changes, push remediation branch, and open a GitHub Pull Request",
    )
    parser.add_argument(
        "--branch",
        default="",
        help="Target base Git branch for Pull Request (default: main)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output display format (default: terminal)",
    )

    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    try:
        use_case = FixDependenciesUseCase()
        fix_unpinned = not parsed_args.vulns_only
        fix_vulns = not parsed_args.unpinned_only

        result = use_case.execute(
            target_path=parsed_args.target,
            dry_run=parsed_args.dry_run,
            fix_unpinned=fix_unpinned,
            fix_vulnerabilities=fix_vulns,
            create_pr=parsed_args.create_pr,
            branch=parsed_args.branch,
        )

        if parsed_args.format == "json":
            sys.stdout.write(json.dumps(result, indent=2) + "\n")
            return 0

        # Terminal output
        prefix = "[DRY RUN] " if parsed_args.dry_run else ""
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(f" Python Hunter {prefix}Automated Dependency Remediation\n")
        sys.stdout.write("==========================================================\n")
        sys.stdout.write(f"Target Path            : {parsed_args.target}\n")
        sys.stdout.write(f"Manifests Modified     : {len(result['files_modified'])}\n")
        sys.stdout.write(f"Dependencies Bumped    : {result['fixes_count']}\n")
        sys.stdout.write("==========================================================\n\n")

        if not result["fixes"]:
            sys.stdout.write("All dependencies are clean, pinned, and up-to-date. No fixes needed.\n")
            return 0

        for fx in result["fixes"]:
            arrow = f"{fx['old_version']} ➔ {fx['new_version']}"
            sys.stdout.write(f" • [{fx['file_path']}] {fx['package_name']}: {arrow}\n")
            sys.stdout.write(f"   Reason: {fx['reason']}\n")

        if result.get("pr_url"):
            sys.stdout.write(f"\n[✓] Automated Remediation PR: {result['pr_url']}\n")
        elif result.get("pr_branch"):
            sys.stdout.write(f"\n[✓] Created remediation branch: {result['pr_branch']}\n")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error executing dependency fixes: {e}\n")
        return 1
