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
from python_hunter.interfaces.cli.commands.attack_paths import (
    register_attack_paths_command,
    handle_attack_paths_command,
)
from python_hunter.interfaces.cli.commands.verify import (
    register_verify_command,
    handle_verify_command,
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

    # Command: attack-paths
    register_attack_paths_command(subparsers)

    # Command: verify
    register_verify_command(subparsers)

    # Command: explain
    explain_p = subparsers.add_parser("explain", help="Explain step-by-step security dataflow evidence and exploitability proof for a finding")
    explain_p.add_argument("finding_id", nargs="?", default=None, help="Finding ID or vulnerability type to explain")
    explain_p.add_argument("--target", default=".", help="Target project path")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Execute security scan on target directory or repository")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan (local directory or remote git URL)")
    scan_parser.add_argument("--branch", default="", help="Git branch to clone/scan")
    scan_parser.add_argument("--commit", default="", help="Specific Git commit SHA to checkout and scan")
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "markdown", "md", "html", "csv"],
        default="terminal",
        help="Output format (terminal, json, sarif, markdown, html, csv)",
    )
    scan_parser.add_argument("-o", "--output", help="Output file path")
    scan_parser.add_argument(
        "--fail-on", default="high", help="Severity threshold to trigger non-zero exit code (critical, high, medium, low)"
    )
    scan_parser.add_argument("--ci", action="store_true", help="Enable CI-friendly execution mode")
    scan_parser.add_argument("--clean", action="store_true", help="Automatically remediate/clean detected malware threats (e.g. PolinRider)")
    scan_parser.add_argument("--language", action="append", help="Target language filter (e.g. java, go, rust)")
    scan_parser.add_argument("--framework", action="append", help="Target framework filter (e.g. spring, django)")

    # Command: clean
    clean_parser = subparsers.add_parser("clean", help="Disinfect repository from malware threats (e.g. PolinRider / TasksJacker)")
    clean_parser.add_argument("target", nargs="?", default=".", help="Target repository directory or remote Git URL to disinfect")
    clean_parser.add_argument("--branch", default="", help="Git branch to clone/disinfect (for remote repositories)")
    clean_parser.add_argument("--dest", default="", help="Local destination directory when disinfecting a remote repository")
    clean_parser.add_argument("--create-pr", action="store_true", help="Automatically push changes and open a GitHub remediation Pull Request")
    clean_parser.add_argument("--threat", choices=["all", "polinrider"], default="all", help="Specific malware threat to clean (default: all)")
    clean_parser.add_argument(
        "--format", choices=["terminal", "json"], default="terminal", help="Output display format (terminal or json)"
    )

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
        service = SecurityApplicationService()
        scan_res = service.execute_secrets_scan(parsed_args.target, scan_history=True)
        if parsed_args.format == "json":
            import json
            sys.stdout.write(json.dumps(scan_res, indent=2) + "\n")
        else:
            sys.stdout.write("==========================================================\n")
            sys.stdout.write(" Python Hunter Credential Exposure Intelligence\n")
            sys.stdout.write("==========================================================\n")
            sys.stdout.write(f"Target Path            : {scan_res['workspace_path']}\n")
            sys.stdout.write(f"Active Exposures       : {scan_res['active_secrets_count']}\n")
            sys.stdout.write(f"Historical Exposures   : {scan_res['historical_secrets_count']}\n")
            sys.stdout.write("==========================================================\n\n")

            for s in scan_res["active_secrets"]:
                sys.stdout.write(f"[!] {s['severity']} SECRET DETECTED ({s['rule_id']})\n")
                sys.stdout.write(f"    Title       : {s['title']}\n")
                sys.stdout.write(f"    File/Line   : {s['file_path']}:{s['line']}\n")
                sys.stdout.write(f"    Fingerprint : {s['fingerprint']}\n")
                sys.stdout.write(f"    Evidence    : {s['evidence']}\n")
                sys.stdout.write("----------------------------------------------------------\n")
        return 0 if scan_res["active_secrets_count"] == 0 else 1

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

    if parsed_args.command == "clean":
        import os
        import subprocess
        from python_hunter.domain.malware.cleaners.polinrider_cleaner import PolinRiderCleaner

        target_input = parsed_args.target.strip()
        is_remote = target_input.startswith(("http://", "https://", "git@")) or target_input.endswith(".git")
        local_path = target_input

        if is_remote:
            from python_hunter.infrastructure.repository.target_resolver import TargetResolver
            resolver = TargetResolver()
            scan_target = resolver.resolve(target_input, branch=getattr(parsed_args, "branch", ""))
            repo_name = scan_target.metadata.get("repo", "repo")
            dest_dir = getattr(parsed_args, "dest", "") or f"./{repo_name}-disinfected"
            dest_dir = os.path.abspath(dest_dir)

            if os.path.exists(dest_dir):
                sys.stderr.write(f"Notice: Destination directory '{dest_dir}' already exists. Disinfecting existing files...\n")
            else:
                sys.stdout.write(f"[*] Cloning remote repository '{target_input}' to '{dest_dir}' ...\n")
                sys.stdout.flush()
                git_env = os.environ.copy()
                git_env["GIT_TERMINAL_PROMPT"] = "0"
                git_env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15"

                clone_cmd = ["git", "clone", "--depth", "1"]
                branch = getattr(parsed_args, "branch", "")
                if branch:
                    clone_cmd.extend(["--branch", branch])
                clone_cmd.extend(["--", scan_target.repository_url, dest_dir])

                proc = subprocess.run(clone_cmd, capture_output=True, text=True, env=git_env)
                if proc.returncode != 0 and scan_target.repository_url.startswith("https://github.com/"):
                    owner = scan_target.metadata.get("owner")
                    repo = scan_target.metadata.get("repo")
                    if owner and repo:
                        ssh_url = f"git@github.com:{owner}/{repo}.git"
                        sys.stdout.write(f"[*] Retrying clone via SSH: {ssh_url} ...\n")
                        sys.stdout.flush()
                        clone_cmd = ["git", "clone", "--depth", "1"]
                        if branch:
                            clone_cmd.extend(["--branch", branch])
                        clone_cmd.extend(["--", ssh_url, dest_dir])
                        proc = subprocess.run(clone_cmd, capture_output=True, text=True, env=git_env)

                if proc.returncode != 0:
                    sys.stderr.write(f"Error: Failed to clone repository '{target_input}': {proc.stderr}\n")
                    return 1

            local_path = dest_dir

        cleaner = PolinRiderCleaner()
        cleanup = cleaner.clean(local_path)
        if getattr(parsed_args, "format", "terminal") == "json":
            import json
            cleanup_dict = {
                "success": cleanup.success,
                "target": target_input,
                "local_path": local_path,
                "tasks_sanitized": cleanup.tasks_sanitized,
                "settings_sanitized": cleanup.settings_sanitized,
                "droppers_deleted": cleanup.droppers_deleted,
                "trojan_fonts_deleted": cleanup.trojan_fonts_deleted,
                "build_configs_cleaned": cleanup.build_configs_cleaned,
                "gitignore_cleaned": cleanup.gitignore_cleaned,
                "details": cleanup.details,
            }
            sys.stdout.write(json.dumps(cleanup_dict, indent=2) + "\n")
        else:
            has_action = bool(
                cleanup.tasks_sanitized
                or cleanup.settings_sanitized
                or cleanup.droppers_deleted
                or cleanup.trojan_fonts_deleted
                or cleanup.build_configs_cleaned
                or cleanup.gitignore_cleaned
            )
            sys.stdout.write("==========================================================\n")
            sys.stdout.write(" Python Hunter Malware Disinfection & Remediation\n")
            sys.stdout.write("==========================================================\n")
            sys.stdout.write(f"Target Repository : {target_input}\n")
            if is_remote:
                sys.stdout.write(f"Disinfected At    : {local_path}\n")
            sys.stdout.write(f"Threat Targeted   : PolinRider / TasksJacker\n")
            sys.stdout.write(f"Status            : {'DISINFECTED' if has_action else 'NO THREATS FOUND'}\n")
            sys.stdout.write("==========================================================\n")
            if cleanup.tasks_sanitized:
                sys.stdout.write(f" [✓] Disinfected tasks.json ({cleanup.tasks_sanitized} malicious tasks removed)\n")
            if cleanup.settings_sanitized:
                sys.stdout.write(f" [✓] Sanitized settings.json ({cleanup.settings_sanitized} settings adjusted)\n")
            if cleanup.droppers_deleted:
                sys.stdout.write(f" [-] Deleted droppers: {', '.join(cleanup.droppers_deleted)}\n")
            if cleanup.trojan_fonts_deleted:
                sys.stdout.write(f" [-] Deleted Trojan fonts: {', '.join(cleanup.trojan_fonts_deleted)}\n")
            if cleanup.build_configs_cleaned:
                sys.stdout.write(f" [*] Cleaned build configs: {', '.join(cleanup.build_configs_cleaned)}\n")
            if cleanup.gitignore_cleaned:
                sys.stdout.write(" [✓] Restored poisoned .gitignore rules\n")
            if cleanup.details:
                sys.stdout.write("\nDetails:\n")
                for d in cleanup.details:
                    sys.stdout.write(f"  • {d}\n")
            if is_remote and has_action:
                if getattr(parsed_args, "create_pr", False):
                    import time
                    sys.stdout.write("\n[*] Creating GitHub Remediation Pull Request ...\n")
                    sys.stdout.flush()
                    ts = int(time.time())
                    pr_branch = f"fix/security-disinfection-{ts}"

                    # Ensure git identity is configured
                    subprocess.run(["git", "config", "user.name", "Python Hunter Security"], cwd=local_path, check=False)
                    subprocess.run(["git", "config", "user.email", "security@python-hunter.local"], cwd=local_path, check=False)

                    # Create branch and commit
                    subprocess.run(["git", "checkout", "-b", pr_branch], cwd=local_path, check=False)
                    subprocess.run(["git", "add", "-A"], cwd=local_path, check=False)
                    commit_msg = "chore(security): remediate PolinRider / TasksJacker malware artifacts\n\nAutomated remediation by Python Hunter"
                    subprocess.run(["git", "commit", "-m", commit_msg], cwd=local_path, check=False)

                    # Push branch
                    push_res = subprocess.run(["git", "push", "-u", "origin", pr_branch], cwd=local_path, capture_output=True, text=True, check=False)
                    if push_res.returncode == 0:
                        sys.stdout.write(f" [✓] Pushed remediation branch: {pr_branch}\n")
                        owner = scan_target.metadata.get("owner", "")
                        repo = scan_target.metadata.get("repo", "")
                        base_b = getattr(parsed_args, "branch", "") or "main"

                        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
                        pr_url = None
                        if token and owner and repo:
                            import urllib.request
                            import json
                            pr_payload = {
                                "title": "chore(security): remediate PolinRider / TasksJacker malware artifacts",
                                "body": (
                                    "## Python Hunter Automated Remediation\n\n"
                                    "This PR was automatically created by **Python Hunter** to disinfect malware artifacts:\n"
                                    f"- Tasks Sanitized: {cleanup.tasks_sanitized}\n"
                                    f"- Settings Sanitized: {cleanup.settings_sanitized}\n"
                                    f"- Dropper Scripts Removed: {len(cleanup.droppers_deleted)}\n"
                                    f"- Trojan Font Payloads Removed: {len(cleanup.trojan_fonts_deleted)}\n"
                                    f"- Build Configs Cleaned: {len(cleanup.build_configs_cleaned)}\n"
                                ),
                                "head": pr_branch,
                                "base": base_b,
                            }
                            req = urllib.request.Request(
                                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                                data=json.dumps(pr_payload).encode("utf-8"),
                                headers={
                                    "Authorization": f"Bearer {token}",
                                    "Accept": "application/vnd.github+json",
                                    "Content-Type": "application/json",
                                    "User-Agent": "Python-Hunter",
                                },
                            )
                            try:
                                with urllib.request.urlopen(req, timeout=15) as resp:
                                    pr_data = json.loads(resp.read().decode("utf-8"))
                                    pr_url = pr_data.get("html_url")
                            except Exception:
                                pass

                        if pr_url:
                            sys.stdout.write(f" [✓] Created Pull Request: {pr_url}\n")
                        else:
                            compare_url = f"https://github.com/{owner}/{repo}/compare/{base_b}...{pr_branch}?expand=1"
                            sys.stdout.write(f" [✓] Open Pull Request via URL: {compare_url}\n")
                    else:
                        sys.stderr.write(f" [!] Failed to push branch '{pr_branch}': {push_res.stderr.strip()}\n")
                else:
                    sys.stdout.write("\nNext Steps to Push Cleaned Repository:\n")
                    sys.stdout.write(f"  cd {local_path}\n")
                    sys.stdout.write("  git status\n")
                    sys.stdout.write("  git commit -am \"chore(security): disinfect PolinRider malware artifacts\"\n")
                    sys.stdout.write("  git push\n")
            sys.stdout.write("==========================================================\n")
        return 0 if cleanup.success else 1

    if parsed_args.command == "scan":
        from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
        from python_hunter.presentation.policy import PolicyEngine
        from python_hunter.presentation.renderer import JsonRenderer, TerminalRenderer

        orchestrator = ScanOrchestrator()
        opts = {
            "ci": getattr(parsed_args, "ci", False),
            "clean": getattr(parsed_args, "clean", False),
            "language": getattr(parsed_args, "language", None),
            "framework": getattr(parsed_args, "framework", None),
        }
        try:
            res = orchestrator.run_scan(
                target_str=parsed_args.target,
                branch=getattr(parsed_args, "branch", ""),
                commit=getattr(parsed_args, "commit", ""),
                tag=getattr(parsed_args, "tag", ""),
                fail_on=getattr(parsed_args, "fail_on", "high"),
                options=opts,
            )
        except Exception as e:
            sys.stderr.write(f"Error during scan: {e}\n")
            return 1

        policy_engine = PolicyEngine()
        exit_code = policy_engine.evaluate(res, fail_on=getattr(parsed_args, "fail_on", "high"))
        res.exit_code = int(exit_code)

        from python_hunter.presentation.renderer import get_renderer

        fmt = getattr(parsed_args, "format", "terminal")
        renderer = get_renderer(fmt)
        output_str = renderer.render(res)

        out_file = getattr(parsed_args, "output", None)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output_str + "\n")
        else:
            sys.stdout.write(output_str + "\n")

        return res.exit_code

    if parsed_args.command in (
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
