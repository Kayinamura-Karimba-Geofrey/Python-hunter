"""CLI Bootstrap Interface for Python Hunter."""

import argparse
import sys
from typing import NoReturn

from python_hunter import __version__
from python_hunter.infrastructure.config.settings import Settings
from python_hunter.interfaces.cli.commands.analyze import run_analyze_command
from python_hunter.interfaces.cli.commands.analyze_ast import run_analyze_ast_command
from python_hunter.interfaces.cli.commands.callgraph import (
    register_callgraph_subcommand,
    run_callgraph_command,
)
from python_hunter.interfaces.cli.commands.ci import run_ci_command
from python_hunter.interfaces.cli.commands.dependencies import run_dependencies_command
from python_hunter.interfaces.cli.commands.discover import run_discover_command
from python_hunter.interfaces.cli.commands.git import (
    register_git_subcommand,
    run_git_command,
)
from python_hunter.interfaces.cli.commands.rules import (
    run_rules_info_command,
    run_rules_list_command,
)
from python_hunter.interfaces.cli.commands.secrets import run_secrets_command
from python_hunter.interfaces.cli.commands.taint import (
    register_taint_subcommand,
    run_taint_command,
)
from python_hunter.interfaces.cli.commands.vulnerabilities import (
    register_vulnerabilities_subcommand,
    run_vulnerabilities_command,
)
from python_hunter.interfaces.cli.commands.languages import (
    register_languages_command,
    handle_languages_command,
)


def create_parser() -> argparse.ArgumentParser:
    """Construct the main CLI command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python-hunter",
        description="Python Hunter — Enterprise Security & Code Intelligence Platform",
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show Python Hunter version and exit"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: version
    subparsers.add_parser("version", help="Show Python Hunter system version details")

    # Command: config
    subparsers.add_parser("config", help="Validate and print current application configuration")

    # Command: discover
    disc_parser = subparsers.add_parser("discover", help="Discover and classify local Python project structure")
    disc_parser.add_argument("target", nargs="?", default=".", help="Target directory or Python file to discover")
    disc_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output display format (text or json)"
    )

    # Command: analyze-ast
    ast_parser = subparsers.add_parser("analyze-ast", help="Execute AST parsing and structural analysis on target project")
    ast_parser.add_argument("target", nargs="?", default=".", help="Target directory or Python file to analyze")
    ast_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output display format (text or json)"
    )

    # Command: analyze
    sec_parser = subparsers.add_parser("analyze", help="Execute unified security analysis, risk scoring, and report generation")
    sec_parser.add_argument("target", nargs="?", default=".", help="Target directory or Python file to analyze")
    sec_parser.add_argument(
        "--format",
        choices=["text", "terminal", "json", "sarif", "markdown", "md", "html", "csv"],
        default="terminal",
        help="Output format (terminal, json, sarif, markdown, html, csv)",
    )
    sec_parser.add_argument("--severity", help="Filter findings by minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    sec_parser.add_argument("--category", help="Filter findings by security category")
    sec_parser.add_argument("--component", help="Filter findings by component/module name")
    sec_parser.add_argument("--status", help="Filter findings by lifecycle state (NEW, EXISTING, RESOLVED, REOPENED, SUPPRESSED)")
    sec_parser.add_argument("--confidence", help="Filter findings by confidence level (HIGH, MEDIUM, LOW)")
    sec_parser.add_argument("--sort", choices=["risk", "severity", "confidence", "file"], default="risk", help="Sort findings by field")
    sec_parser.add_argument("--limit", type=int, help="Limit maximum returned findings")
    sec_parser.add_argument("-o", "--output", help="Write report output to specified file path")
    sec_parser.add_argument("--details", action="store_true", help="Display full evidence, attack paths, and remediation details")
    sec_parser.add_argument("--explain-flow", action="store_true", help="Explain step-by-step interprocedural dataflow propagation")
    sec_parser.add_argument("--show-trace", action="store_true", help="Show exact source -> intermediate -> sink trace")
    sec_parser.add_argument("--analysis-depth", type=int, default=10, help="Maximum interprocedural call graph search depth")
    sec_parser.add_argument("--max-paths", type=int, default=100, help="Maximum interprocedural paths to analyze")
    sec_parser.add_argument("--max-call-depth", type=int, default=10, help="Maximum recursion/call depth limit")
    sec_parser.add_argument("--dependencies", action="store_true", help="Perform Software Composition Analysis (SCA) dependency scan")
    sec_parser.add_argument("--dependencies-tree", action="store_true", help="Display ascii dependency tree graph")
    sec_parser.add_argument("--vulnerabilities", action="store_true", help="Display vulnerable dependencies and reachability traces")
    sec_parser.add_argument("--quiet", action="store_true", help="Output concise status summary only")
    sec_parser.add_argument("--verbose", action="store_true", help="Display analyzer timing and health execution metrics")
    sec_parser.add_argument("--no-redact", action="store_true", help="Disable automatic secret redaction")

    # Command: ci
    ci_p = subparsers.add_parser("ci", help="Run CI pipeline security analysis, baseline evaluation, and artifact generation")
    ci_p.add_argument("target", nargs="?", default=".", help="Target directory to analyze")
    ci_p.add_argument("--output-dir", default=".", help="Directory to save report artifacts (report.json, report.sarif, report.md)")
    ci_p.add_argument("--no-artifacts", action="store_true", help="Disable report artifact files export")
    ci_p.add_argument("--quiet", action="store_true", help="Output concise status summary only")
    ci_p.add_argument("--verbose", action="store_true", help="Display execution timing and health metrics")
    ci_p.add_argument("--no-redact", action="store_true", help="Disable secret redaction")

    # Command: gate
    gate_p = subparsers.add_parser("gate", help="Evaluate CI/CD security gate policy")
    gate_p.add_argument("target", nargs="?", default=".", help="Target directory to evaluate")

    # Command: baseline
    base_p = subparsers.add_parser("baseline", help="Manage baseline finding snapshots")
    base_sub = base_p.add_subparsers(dest="baseline_action", help="Baseline actions")
    create_b = base_sub.add_parser("create", help="Create baseline snapshot")
    create_b.add_argument("target", nargs="?", default=".", help="Target path")
    create_b.add_argument("--output", default="pyh_baseline.json", help="Output baseline file path")

    # Command: diff
    diff_p = subparsers.add_parser("diff", help="Diff two scan output JSON files")
    diff_p.add_argument("old_scan", help="Path to previous scan JSON file")
    diff_p.add_argument("new_scan", help="Path to current scan JSON file")

    # Command: rules
    rules_parser = subparsers.add_parser("rules", help="Manage security rules taxonomy")
    rules_sub = rules_parser.add_subparsers(dest="rules_action", help="Rule actions")
    rules_sub.add_parser("list", help="List all registered security rules")
    rules_info_p = rules_sub.add_parser("info", help="View details of a specific security rule")
    rules_info_p.add_argument("rule_id", help="Security rule ID (e.g. PYH-AST-001)")

    # Command: secrets
    sec_secrets_parser = subparsers.add_parser("secrets", help="Scan for exposed secrets and credentials")
    sec_secrets_parser.add_argument("target", nargs="?", default=".", help="Target directory or file to scan for secrets")
    sec_secrets_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output display format (text or json)"
    )

    # Command: dependencies
    dep_cmd_parser = subparsers.add_parser("dependencies", help="Analyze project dependencies and supply-chain security")
    dep_cmd_parser.add_argument("target", nargs="?", default=".", help="Target directory or manifest file to analyze")
    dep_cmd_parser.add_argument("--tree", action="store_true", help="Display ascii dependency tree")
    dep_cmd_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output display format (text or json)"
    )

    # Command: vulnerabilities
    register_vulnerabilities_subcommand(subparsers)

    # Command: git
    register_git_subcommand(subparsers)

    # Command: github
    github_p = subparsers.add_parser("github", help="Manage GitHub App integration, repositories, PRs, and webhooks")
    github_sub = github_p.add_subparsers(dest="github_action", help="GitHub actions")
    github_sub.add_parser("connect", help="Connect to GitHub App")
    github_sub.add_parser("repositories", help="List monitored GitHub repositories")
    github_sub.add_parser("prs", help="List PR security scan results")
    github_sub.add_parser("status", help="View GitHub webhook status")

    # Command: taint
    register_taint_subcommand(subparsers)

    # Command: callgraph
    register_callgraph_subcommand(subparsers)

    # Command: languages
    register_languages_command(subparsers)

    # Command: explain
    explain_p = subparsers.add_parser("explain", help="Explain step-by-step security dataflow evidence and exploitability proof for a finding")
    explain_p.add_argument("finding_id", nargs="?", default=None, help="Finding ID or vulnerability type to explain")
    explain_p.add_argument("--target", default=".", help="Target project path")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Execute security scan on target directory or repository")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan")
    scan_parser.add_argument("--language", action="append", help="Target language filter (e.g. java, go, rust)")
    scan_parser.add_argument("--framework", action="append", help="Target framework filter (e.g. spring, django)")

    subparsers.add_parser("project", help="Manage project records")
    subparsers.add_parser("sbom", help="Generate CycloneDX/SPDX SBOM")
    subparsers.add_parser("report", help="Generate security reports")
    subparsers.add_parser("plugins", help="Manage third-party plugins")

    return parser


def run_cli(args: list[str] | None = None) -> int:
    """Run CLI execution flow."""
    parser = create_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    if parsed_args.version or parsed_args.command == "version":
        sys.stdout.write(f"Python Hunter version {__version__} (Python {sys.version.split()[0]})\n")
        return 0

    if parsed_args.command == "config":
        try:
            settings = Settings.load_from_env()
            sys.stdout.write("--- Python Hunter Configuration ---\n")
            sys.stdout.write(f"Environment: {settings.app.env}\n")
            sys.stdout.write(f"Log Level: {settings.log.level} (Format: {settings.log.format})\n")
            sys.stdout.write(f"Max Scan File Size: {settings.scan.max_file_size_mb} MB\n")
            sys.stdout.write(f"Scan Timeout: {settings.scan.timeout_seconds} s\n")
            sys.stdout.write(f"Min Severity Threshold: {settings.scan.min_severity}\n")
            return 0
        except Exception as e:
            sys.stderr.write(f"Error loading configuration: {e}\n")
            return 1

    if parsed_args.command == "discover":
        return run_discover_command(parsed_args.target, output_format=parsed_args.format)

    if parsed_args.command == "analyze-ast":
        return run_analyze_ast_command(parsed_args.target, output_format=parsed_args.format)

    if parsed_args.command == "analyze":
        return run_analyze_command(parsed_args)

    if parsed_args.command == "ci":
        return run_ci_command(parsed_args)

    if parsed_args.command == "secrets":
        return run_secrets_command([parsed_args.target, "--format", parsed_args.format])

    if parsed_args.command == "dependencies":
        cmd_args = [parsed_args.target, "--format", parsed_args.format]
        if getattr(parsed_args, "tree", False):
            cmd_args.append("--tree")
        return run_dependencies_command(cmd_args)

    if parsed_args.command == "vulnerabilities":
        v_args = [parsed_args.target, "--format", parsed_args.format]
        if getattr(parsed_args, "details", False):
            v_args.append("--details")
        if getattr(parsed_args, "offline", False):
            v_args.append("--offline")
        if getattr(parsed_args, "fail_on", None):
            v_args.extend(["--fail-on", parsed_args.fail_on])
        return run_vulnerabilities_command(v_args)

    if parsed_args.command == "git":
        return run_git_command(parsed_args)

    if parsed_args.command == "github":
        from python_hunter.application.services.security_app_service import SecurityApplicationService
        svc = SecurityApplicationService()
        action = getattr(parsed_args, "github_action", "status")
        if action == "connect":
            token = svc.github_app.generate_jwt()
            sys.stdout.write(f"Connected to GitHub App. JWT: {token[:12]}...\n")
            return 0
        elif action == "repositories":
            repos = svc.list_repositories()
            sys.stdout.write(f"Monitored GitHub Repositories ({len(repos)}):\n")
            for r in repos:
                sys.stdout.write(f"  • {r['name']} — Score: {r['security_score']}/100 [{r['risk_level']}]\n")
            return 0
        elif action == "prs":
            prs = svc.list_pull_requests()
            sys.stdout.write(f"Pull Request Security Scans ({len(prs)}):\n")
            for p in prs:
                sys.stdout.write(f"  PR #{p['pr_number']}: {p['title']} [{p['policy_result']}] Score: {p['security_score']}/100 (Delta: {p['score_delta']:+d})\n")
            return 0
        else:
            st = svc.get_webhook_status()
            sys.stdout.write("--- GitHub Integration Status ---\n")
            sys.stdout.write(f"  Webhook Listener: ACTIVE\n  Total Events: {st['total_events']}\n  Completed: {st['completed']}\n  Dead Letter: {st['dead_letter_count']}\n")
            return 0

    if parsed_args.command == "taint":
        return run_taint_command(parsed_args)

    if parsed_args.command == "callgraph":
        return run_callgraph_command(parsed_args)

    if parsed_args.command == "languages":
        handle_languages_command(parsed_args)
        return 0

    if parsed_args.command == "gate":
        from python_hunter.interfaces.cli.commands.gate import run_gate_command
        return run_gate_command(parsed_args)

    if parsed_args.command == "baseline":
        from python_hunter.interfaces.cli.commands.baseline import run_baseline_command
        return run_baseline_command(parsed_args)

    if parsed_args.command == "diff":
        from python_hunter.interfaces.cli.commands.baseline import run_diff_command
        return run_diff_command(parsed_args)

    if parsed_args.command == "explain":
        from python_hunter.interfaces.cli.commands.explain import run_explain_command
        return run_explain_command(parsed_args)

    if parsed_args.command == "rules":
        if parsed_args.rules_action == "list" or not parsed_args.rules_action:
            return run_rules_list_command()
        elif parsed_args.rules_action == "info":
            return run_rules_info_command(parsed_args.rule_id)

    if parsed_args.command in (
        "scan",
        "project",
        "dependencies",
        "secrets",
        "git",
        "sbom",
        "report",
        "plugins",
    ):
        sys.stdout.write(
            f"Notice: Command '{parsed_args.command}' is registered. Functionality will be implemented in subsequent development steps.\n"
        )
        return 0

    if not parsed_args.command:
        parser.print_help()
        return 0

    return 0


def cli() -> NoReturn:
    """Entry point wrapper for script invocation."""
    sys.exit(run_cli())


if __name__ == "__main__":
    cli()
