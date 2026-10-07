"""CLI commands for GitHub App integration, monitored repositories, PR scans, and webhooks."""

import argparse
import sys

from python_hunter.application.services.security_app_service import SecurityApplicationService


def register_github_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'github' command group."""
    github_p = subparsers.add_parser("github", help="Manage GitHub App integration, repositories, PRs, and webhooks")
    github_sub = github_p.add_subparsers(dest="github_action", help="GitHub actions")
    github_sub.add_parser("connect", help="Connect to GitHub App")
    github_sub.add_parser("repositories", help="List monitored GitHub repositories")
    github_sub.add_parser("prs", help="List PR security scan results")
    github_sub.add_parser("status", help="View GitHub webhook status")


def run_github_command(args: argparse.Namespace) -> int:
    svc = SecurityApplicationService()
    action = getattr(args, "github_action", None) or "status"

    if action == "connect":
        token = svc.github_app.generate_jwt()
        sys.stdout.write(f"Connected to GitHub App. JWT: {svc.github_app.mask_token(token)}\n")
        return 0

    if action == "repositories":
        repos = [r for r in svc.list_repositories() if r["provider"] == "github"]
        sys.stdout.write(f"Monitored GitHub Repositories ({len(repos)}):\n")
        for r in repos:
            sys.stdout.write(f"  • {r['name']} — Score: {r['security_score']}/100 [{r['risk_level']}]\n")
        return 0

    if action == "prs":
        prs = svc.list_pull_requests()
        sys.stdout.write(f"Pull Request Security Scans ({len(prs)}):\n")
        for p in prs:
            sys.stdout.write(
                f"  PR #{p['pr_number']}: {p['title']} [{p['policy_result']}] "
                f"Score: {p['security_score']}/100 (Delta: {p['score_delta']:+d})\n"
            )
        return 0

    st = svc.get_webhook_status()
    sys.stdout.write("--- GitHub Integration Status ---\n")
    sys.stdout.write(
        f"  Webhook Listener: ACTIVE\n  Total Events: {st['total_events']}\n"
        f"  Completed: {st['completed']}\n  Dead Letter: {st['dead_letter_count']}\n"
    )
    return 0
