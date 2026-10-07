"""CLI command for disinfecting repositories from PolinRider / TasksJacker malware artifacts."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from typing import Any

from python_hunter.domain.malware.cleaners.polinrider_cleaner import PolinRiderCleaner

RULE = "==========================================================\n"


def register_clean_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'clean' command."""
    clean_parser = subparsers.add_parser("clean", help="Disinfect repository from malware threats (e.g. PolinRider / TasksJacker)")
    clean_parser.add_argument("target", nargs="?", default=".", help="Target repository directory or remote Git URL to disinfect")
    clean_parser.add_argument("--branch", default="", help="Git branch to clone/disinfect (for remote repositories)")
    clean_parser.add_argument("--dest", default="", help="Local destination directory when disinfecting a remote repository")
    clean_parser.add_argument("--create-pr", action="store_true", help="Automatically push changes and open a GitHub remediation Pull Request")
    clean_parser.add_argument("--threat", choices=["all", "polinrider"], default="all", help="Specific malware threat to clean (default: all)")
    clean_parser.add_argument(
        "--format", choices=["terminal", "json"], default="terminal", help="Output display format (terminal or json)"
    )
    clean_parser.add_argument("--timeout", type=int, default=None, help="Wall-clock timeout in seconds for repository clone")
    clean_parser.add_argument(
        "--idle-timeout", type=int, default=None, help="Inactivity timeout in seconds before aborting stalled git clone"
    )


def run_clean_command(args: argparse.Namespace) -> int:
    target_input = args.target.strip()
    is_remote = target_input.startswith(("http://", "https://", "git@")) or target_input.endswith(".git")
    local_path = target_input
    scan_target = None

    if is_remote:
        from python_hunter.infrastructure.repository import RepositoryManager, TargetResolver

        scan_target = TargetResolver().resolve(target_input, branch=args.branch)
        repo_name = scan_target.metadata.get("repo", "repo")
        dest_dir = os.path.abspath(args.dest or f"./{repo_name}-disinfected")

        if os.path.exists(dest_dir):
            error = _check_existing_destination(dest_dir, scan_target.metadata)
            if error:
                sys.stderr.write(error)
                return 1
            sys.stderr.write(f"Notice: Destination directory '{dest_dir}' already exists. Disinfecting existing files...\n")
            local_path = dest_dir
        else:
            try:
                local_path = RepositoryManager().acquire_target(
                    scan_target, dest_dir=dest_dir, timeout=args.timeout, idle_timeout=args.idle_timeout
                )
            except Exception as e:
                sys.stderr.write(f"Error: Failed to clone repository '{target_input}': {e}\n")
                return 1

    cleanup = PolinRiderCleaner().clean(local_path)

    if args.format == "json":
        sys.stdout.write(
            json.dumps(
                {
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
                },
                indent=2,
            )
            + "\n"
        )
        return 0 if cleanup.success else 1

    has_action = _render_cleanup(cleanup, target_input, local_path, is_remote)
    if is_remote and has_action and scan_target is not None:
        if args.create_pr:
            _create_remediation_pr(cleanup, local_path, scan_target.metadata, args.branch or "main")
        else:
            sys.stdout.write("\nNext Steps to Push Cleaned Repository:\n")
            sys.stdout.write(f"  cd {local_path}\n")
            sys.stdout.write("  git status\n")
            sys.stdout.write('  git commit -am "chore(security): disinfect PolinRider malware artifacts"\n')
            sys.stdout.write("  git push\n")
    sys.stdout.write(RULE)
    return 0 if cleanup.success else 1


def _check_existing_destination(dest_dir: str, metadata: dict[str, Any]) -> str | None:
    """Refuse to disinfect a pre-existing directory that is not a clone of the requested repository."""
    dest_git_config = os.path.join(dest_dir, ".git", "config")
    if not os.path.isfile(dest_git_config):
        return (
            f"Error: Destination '{dest_dir}' exists but is not a git repository clone. "
            "Remove it or choose another --dest directory.\n"
        )
    try:
        with open(dest_git_config, encoding="utf-8", errors="ignore") as f:
            cfg = f.read()
    except OSError:
        cfg = ""
    owner, repo = metadata.get("owner", ""), metadata.get("repo", "")
    if owner and repo and f"github.com/{owner}/{repo}" not in cfg:
        return (
            f"Error: Destination '{dest_dir}' belongs to a different repository "
            f"than '{owner}/{repo}'. Refusing to disinfect.\n"
        )
    return None


def _render_cleanup(cleanup: Any, target_input: str, local_path: str, is_remote: bool) -> bool:
    has_action = bool(
        cleanup.tasks_sanitized
        or cleanup.settings_sanitized
        or cleanup.droppers_deleted
        or cleanup.trojan_fonts_deleted
        or cleanup.build_configs_cleaned
        or cleanup.gitignore_cleaned
    )
    out = sys.stdout
    out.write(RULE)
    out.write(" Python Hunter Malware Disinfection & Remediation\n")
    out.write(RULE)
    out.write(f"Target Repository : {target_input}\n")
    if is_remote:
        out.write(f"Disinfected At    : {local_path}\n")
    out.write("Threat Targeted   : PolinRider / TasksJacker\n")
    out.write(f"Status            : {'DISINFECTED' if has_action else 'NO THREATS FOUND'}\n")
    out.write(RULE)
    if cleanup.tasks_sanitized:
        out.write(f" [✓] Disinfected tasks.json ({cleanup.tasks_sanitized} malicious tasks removed)\n")
    if cleanup.settings_sanitized:
        out.write(f" [✓] Sanitized settings.json ({cleanup.settings_sanitized} settings adjusted)\n")
    if cleanup.droppers_deleted:
        out.write(f" [-] Deleted droppers: {', '.join(cleanup.droppers_deleted)}\n")
    if cleanup.trojan_fonts_deleted:
        out.write(f" [-] Deleted Trojan fonts: {', '.join(cleanup.trojan_fonts_deleted)}\n")
    if cleanup.build_configs_cleaned:
        out.write(f" [*] Cleaned build configs: {', '.join(cleanup.build_configs_cleaned)}\n")
    if cleanup.gitignore_cleaned:
        out.write(" [✓] Restored poisoned .gitignore rules\n")
    if cleanup.details:
        out.write("\nDetails:\n")
        for d in cleanup.details:
            out.write(f"  • {d}\n")
    return has_action


def _create_remediation_pr(cleanup: Any, local_path: str, metadata: dict[str, Any], base_branch: str) -> None:
    sys.stdout.write("\n[*] Creating GitHub Remediation Pull Request ...\n")
    sys.stdout.flush()
    pr_branch = f"fix/security-disinfection-{int(time.time())}"

    git_bin = shutil.which("git") or "git"

    def git(*cmd: str) -> subprocess.CompletedProcess[str]:
        # Fixed git subcommands; arguments are generated here, never taken from the scanned repo.
        return subprocess.run(  # noqa: S603
            [git_bin, *cmd], cwd=local_path, capture_output=True, text=True, check=False
        )

    git("config", "user.name", "Python Hunter Security")
    git("config", "user.email", "security@python-hunter.local")
    git("checkout", "-b", pr_branch)
    git("add", "-A")
    git(
        "commit",
        "-m",
        "chore(security): remediate PolinRider / TasksJacker malware artifacts\n\nAutomated remediation by Python Hunter",
    )
    push_res = git("push", "-u", "origin", pr_branch)
    if push_res.returncode != 0:
        sys.stderr.write(f" [!] Failed to push branch '{pr_branch}': {push_res.stderr.strip()}\n")
        return

    sys.stdout.write(f" [✓] Pushed remediation branch: {pr_branch}\n")
    owner, repo = metadata.get("owner", ""), metadata.get("repo", "")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    pr_url = None
    if token and owner and repo:
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
            "base": base_branch,
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
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed https URL
                pr_url = json.loads(resp.read().decode("utf-8")).get("html_url")
        except Exception as e:
            sys.stderr.write(f" [!] GitHub API pull request creation failed: {e}\n")

    if pr_url:
        sys.stdout.write(f" [✓] Created Pull Request: {pr_url}\n")
    else:
        compare_url = f"https://github.com/{owner}/{repo}/compare/{base_branch}...{pr_branch}?expand=1"
        sys.stdout.write(f" [✓] Open Pull Request via URL: {compare_url}\n")
