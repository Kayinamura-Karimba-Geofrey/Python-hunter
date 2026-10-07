"""CLI Bootstrap Interface for Python Hunter."""

import argparse
import sys
from collections.abc import Callable
from typing import NoReturn

from python_hunter import __version__
from python_hunter.infrastructure.config.settings import Settings
from python_hunter.interfaces.cli.commands.analyze import run_analyze_command
from python_hunter.interfaces.cli.commands.analyze_ast import run_analyze_ast_command
from python_hunter.interfaces.cli.commands.attack_paths import (
    handle_attack_paths_command,
    register_attack_paths_command,
)
from python_hunter.interfaces.cli.commands.callgraph import (
    register_callgraph_subcommand,
    run_callgraph_command,
)
from python_hunter.interfaces.cli.commands.ci import run_ci_command
from python_hunter.interfaces.cli.commands.clean import register_clean_command, run_clean_command
from python_hunter.interfaces.cli.commands.dependencies import run_dependencies_command
from python_hunter.interfaces.cli.commands.discover import run_discover_command
from python_hunter.interfaces.cli.commands.git import (
    register_git_subcommand,
    run_git_command,
)
from python_hunter.interfaces.cli.commands.github import register_github_command, run_github_command
from python_hunter.interfaces.cli.commands.governance import register_org_command, run_org_command
from python_hunter.interfaces.cli.commands.integrations import (
    register_integrations_command,
    run_integrations_command,
)
from python_hunter.interfaces.cli.commands.intelligence import (
    register_intelligence_commands,
    run_intelligence_command,
    run_posture_command,
    run_remediation_command,
    run_trends_command,
)
from python_hunter.interfaces.cli.commands.languages import (
    handle_languages_command,
    register_languages_command,
)
from python_hunter.interfaces.cli.commands.operations import (
    register_operations_commands,
    run_alerts_command,
    run_health_command,
    run_incidents_command,
    run_jobs_command,
    run_monitor_command,
)
from python_hunter.interfaces.cli.commands.rules import (
    run_rules_info_command,
    run_rules_list_command,
)
from python_hunter.interfaces.cli.commands.scan import register_scan_command, run_scan_command
from python_hunter.interfaces.cli.commands.secrets import run_workspace_secrets_command
from python_hunter.interfaces.cli.commands.taint import (
    register_taint_subcommand,
    run_taint_command,
)
from python_hunter.interfaces.cli.commands.verify import (
    handle_verify_command,
    register_verify_command,
)
from python_hunter.interfaces.cli.commands.vulnerabilities import (
    register_vulnerabilities_subcommand,
    run_vulnerabilities_command,
)

HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "scan": run_scan_command,
    "clean": run_clean_command,
    "github": run_github_command,
    "intelligence": run_intelligence_command,
    "posture": run_posture_command,
    "remediation": run_remediation_command,
    "trends": run_trends_command,
    "monitor": run_monitor_command,
    "alerts": run_alerts_command,
    "incidents": run_incidents_command,
    "jobs": run_jobs_command,
    "health": run_health_command,
    "org": run_org_command,
    "integrations": run_integrations_command,
}


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

    register_github_command(subparsers)

    # Command: taint
    register_taint_subcommand(subparsers)

    # Command: callgraph
    register_callgraph_subcommand(subparsers)

    # Command: languages
    register_languages_command(subparsers)

    # Command: attack-paths
    register_attack_paths_command(subparsers)

    # Command: verify
    register_verify_command(subparsers)

    # Command: explain
    explain_p = subparsers.add_parser("explain", help="Explain step-by-step security dataflow evidence and exploitability proof for a finding")
    explain_p.add_argument("finding_id", nargs="?", default=None, help="Finding ID or vulnerability type to explain")
    explain_p.add_argument("--target", default=".", help="Target project path")

    register_scan_command(subparsers)
    register_clean_command(subparsers)
    register_intelligence_commands(subparsers)
    register_operations_commands(subparsers)
    register_org_command(subparsers)
    register_integrations_command(subparsers)

    # Command: sbom
    sbom_parser = subparsers.add_parser(
        "sbom", help="Generate CycloneDX 1.5 or SPDX 2.3 Software Bill of Materials (SBOM)"
    )
    sbom_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or manifest file (default: .)",
    )
    sbom_parser.add_argument(
        "--format",
        "-f",
        choices=["cyclonedx", "cdx", "spdx", "spdx-json"],
        default="cyclonedx",
        help="SBOM standard format (default: cyclonedx)",
    )
    sbom_parser.add_argument(
        "--spec-version",
        default=None,
        help="Specification version (e.g. 1.5, 1.4 for CycloneDX; 2.3, 2.2 for SPDX)",
    )
    sbom_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    sbom_parser.add_argument(
        "--include-vulns",
        action="store_true",
        help="Embed matched vulnerability findings into CycloneDX SBOM document",
    )

    # Command: report
    report_parser = subparsers.add_parser(
        "report", help="Generate executive, compliance, and developer security reports"
    )
    report_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or manifest file to audit (default: .)",
    )
    report_parser.add_argument(
        "--type",
        choices=["executive", "compliance", "technical"],
        default="executive",
        help="Report archetype (default: executive)",
    )
    report_parser.add_argument(
        "--format",
        "-f",
        choices=["html", "markdown", "md", "json"],
        default="html",
        help="Report export format (default: html)",
    )
    report_parser.add_argument(
        "--framework",
        default="owasp-top-10",
        help="Compliance framework benchmark (e.g. owasp-top-10, nist, soc-2, iso27001, cis)",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: python-hunter-report.html or stdout)",
    )
    report_parser.add_argument(
        "--organization",
        default="Enterprise Security",
        help="Organization or team name to appear on report header",
    )
    report_parser.add_argument(
        "--title",
        default=None,
        help="Custom report title",
    )

    # Command: fix
    fix_parser = subparsers.add_parser(
        "fix", help="Automatically bump and pin vulnerable or unconstrained dependencies"
    )
    fix_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or repository (default: .)",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview proposed dependency updates without writing changes to disk",
    )
    fix_parser.add_argument(
        "--unpinned-only",
        action="store_true",
        help="Only pin unconstrained or broad dependencies",
    )
    fix_parser.add_argument(
        "--vulns-only",
        action="store_true",
        help="Only fix dependencies matching known vulnerability advisories",
    )
    fix_parser.add_argument(
        "--create-pr",
        action="store_true",
        help="Commit changes, push remediation branch, and open a GitHub Pull Request",
    )
    fix_parser.add_argument(
        "--branch",
        default="",
        help="Target base Git branch for Pull Request (default: main)",
    )
    fix_parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output display format (default: terminal)",
    )

    # Command: tui
    tui_parser = subparsers.add_parser(
        "tui", help="Launch interactive terminal dashboard to inspect findings and attack paths"
    )
    tui_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or repository (default: .)",
    )
    tui_parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Print terminal dashboard snapshot and exit without launching curses UI",
    )

    # Command: lsp
    lsp_parser = subparsers.add_parser(
        "lsp", help="Run Language Server Protocol (LSP 3.17) server for real-time in-editor security diagnostics"
    )
    lsp_parser.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Run language server over standard input and output (default, used by VS Code / Neovim)",
    )
    lsp_parser.add_argument(
        "--tcp",
        metavar="[HOST:]PORT",
        default="",
        help="Listen for LSP client connections over TCP (e.g. 2087 or 127.0.0.1:2087)",
    )
    lsp_parser.add_argument(
        "--log-file",
        metavar="PATH",
        default="",
        help="Log server operations and JSON-RPC wire messages to specified file",
    )

    # Command: diagnostics
    diag_parser = subparsers.add_parser(
        "diagnostics", help="Emit security diagnostics in editor-friendly formats (gcc, lsp, codeclimate, rdjson)"
    )
    diag_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or project directory to evaluate (default: .)",
    )
    diag_parser.add_argument(
        "--format",
        choices=["gcc", "lsp", "json", "codeclimate", "rdjson"],
        default="gcc",
        help="Output format (default: gcc)",
    )
    diag_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Exit with failure status if findings meet or exceed severity (default: high)",
    )

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
        return run_workspace_secrets_command(parsed_args.target, parsed_args.format)

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

    if parsed_args.command == "sbom":
        from python_hunter.interfaces.cli.commands.sbom import run_sbom_command

        s_args = [parsed_args.target, "--format", parsed_args.format]
        if getattr(parsed_args, "spec_version", None):
            s_args.extend(["--spec-version", parsed_args.spec_version])
        if getattr(parsed_args, "output", None):
            s_args.extend(["-o", parsed_args.output])
        if getattr(parsed_args, "include_vulns", False):
            s_args.append("--include-vulns")
        return run_sbom_command(s_args)

    if parsed_args.command == "report":
        from python_hunter.interfaces.cli.commands.report import run_report_command

        r_args = [parsed_args.target, "--type", parsed_args.type, "--format", parsed_args.format]
        if getattr(parsed_args, "framework", None):
            r_args.extend(["--framework", parsed_args.framework])
        if getattr(parsed_args, "output", None):
            r_args.extend(["-o", parsed_args.output])
        if getattr(parsed_args, "organization", None):
            r_args.extend(["--organization", parsed_args.organization])
        if getattr(parsed_args, "title", None):
            r_args.extend(["--title", parsed_args.title])
        return run_report_command(r_args)

    if parsed_args.command == "fix":
        from python_hunter.interfaces.cli.commands.fix import run_fix_command

        f_args = [parsed_args.target, "--format", parsed_args.format]
        if getattr(parsed_args, "dry_run", False):
            f_args.append("--dry-run")
        if getattr(parsed_args, "unpinned_only", False):
            f_args.append("--unpinned-only")
        if getattr(parsed_args, "vulns_only", False):
            f_args.append("--vulns-only")
        if getattr(parsed_args, "create_pr", False):
            f_args.append("--create-pr")
        if getattr(parsed_args, "branch", ""):
            f_args.extend(["--branch", parsed_args.branch])
        return run_fix_command(f_args)

    if parsed_args.command == "tui":
        from python_hunter.interfaces.cli.commands.tui import run_tui_command

        t_args = [parsed_args.target]
        if getattr(parsed_args, "snapshot", False):
            t_args.append("--snapshot")
        return run_tui_command(t_args)

    if parsed_args.command == "lsp":
        from python_hunter.interfaces.cli.commands.lsp import run_lsp_command

        l_args = []
        if getattr(parsed_args, "tcp", ""):
            l_args.extend(["--tcp", parsed_args.tcp])
        if getattr(parsed_args, "log_file", ""):
            l_args.extend(["--log-file", parsed_args.log_file])
        return run_lsp_command(l_args)

    if parsed_args.command == "diagnostics":
        from python_hunter.interfaces.cli.commands.diagnostics import run_diagnostics_command

        d_args = [
            parsed_args.target,
            "--format",
            parsed_args.format,
            "--fail-on",
            parsed_args.fail_on,
        ]
        return run_diagnostics_command(d_args)

    if parsed_args.command == "taint":
        return run_taint_command(parsed_args)

    if parsed_args.command == "callgraph":
        return run_callgraph_command(parsed_args)

    if parsed_args.command == "languages":
        handle_languages_command(parsed_args)
        return 0

    if parsed_args.command == "attack-paths":
        return handle_attack_paths_command(parsed_args)

    if parsed_args.command == "verify":
        return handle_verify_command(parsed_args)

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

    if parsed_args.command in HANDLERS:
        return HANDLERS[parsed_args.command](parsed_args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    return 0


def cli() -> NoReturn:
    """Entry point wrapper for script invocation."""
    sys.exit(run_cli())


if __name__ == "__main__":
    cli()
