"""CLI Bootstrap Interface for Python Hunter."""

import argparse
import sys
from typing import NoReturn

from python_hunter import __version__
from python_hunter.infrastructure.config.settings import Settings
from python_hunter.interfaces.cli.commands.analyze import run_analyze_command
from python_hunter.interfaces.cli.commands.analyze_ast import run_analyze_ast_command
from python_hunter.interfaces.cli.commands.discover import run_discover_command
from python_hunter.interfaces.cli.commands.rules import (
    run_rules_info_command,
    run_rules_list_command,
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
    sec_parser = subparsers.add_parser("analyze", help="Execute AST security analysis and rule evaluation on target project")
    sec_parser.add_argument("target", nargs="?", default=".", help="Target directory or Python file to analyze")
    sec_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output display format (text or json)"
    )

    # Command: rules
    rules_parser = subparsers.add_parser("rules", help="Manage security rules taxonomy")
    rules_sub = rules_parser.add_subparsers(dest="rules_action", help="Rule actions")
    rules_sub.add_parser("list", help="List all registered security rules")
    rules_info_p = rules_sub.add_parser("info", help="View details of a specific security rule")
    rules_info_p.add_argument("rule_id", help="Security rule ID (e.g. PYH-AST-001)")

    # Future subcommands (stubs marking development roadmap)
    scan_parser = subparsers.add_parser("scan", help="Execute security scan on target directory or repository")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan")

    subparsers.add_parser("project", help="Manage project records (Milestone 10/11)")
    subparsers.add_parser("dependencies", help="Scan dependency manifests (Step 6 / Milestone 6)")
    subparsers.add_parser("secrets", help="Scan for secret leaks (Step 5 / Milestone 5)")
    subparsers.add_parser("git", help="Scan Git repository history (Step 7 / Milestone 7)")
    subparsers.add_parser("sbom", help="Generate CycloneDX/SPDX SBOM (Milestone 13)")
    subparsers.add_parser("report", help="Generate security reports (Milestone 13)")
    subparsers.add_parser("plugins", help="Manage third-party plugins (Milestone 17)")

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
        return run_analyze_command(parsed_args.target, output_format=parsed_args.format)

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
