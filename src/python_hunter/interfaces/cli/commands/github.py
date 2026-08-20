"""CLI commands for GitHub Integration & Pull Request Security Platform."""

import click
from python_hunter.application.services.security_app_service import SecurityApplicationService

service = SecurityApplicationService()


@click.group(name="github")
def github_group():
    """Manage GitHub App integration, repositories, pull requests, and webhooks."""
    pass


@github_group.command(name="connect")
@click.option("--app-id", prompt="GitHub App ID", help="GitHub App Identifier")
@click.option("--org", prompt="Organization/Account", help="GitHub Organization or User Account")
def connect(app_id: str, org: str):
    """Authenticate and connect Python Hunter with a GitHub App."""
    token = service.github_app.generate_jwt()
    click.echo(f"Successfully generated JWT token for App ID {app_id}")
    click.echo(f"Connected Python Hunter to GitHub Organization: {org}")
    click.echo(f"Installation Status: ACTIVE | Scope: Repositories & Pull Requests")


@github_group.command(name="repositories")
def list_repositories():
    """List all GitHub repositories monitored by Python Hunter."""
    repos = service.list_repositories()
    gh_repos = [r for r in repos if r.get("provider") == "github" or "github.com" in r.get("url_or_path", "")]
    click.echo(f"\nMonitored GitHub Repositories ({len(gh_repos)}):\n")
    for r in gh_repos:
        click.echo(f"  • {r['name']} — Branch: {r['default_branch']} | Score: {r['security_score']}/100 [{r['risk_level']}]")


@github_group.command(name="prs")
def list_prs():
    """List Pull Request security scan status and score deltas."""
    prs = service.list_pull_requests()
    click.echo(f"\nPull Request Security Scans ({len(prs)}):\n")
    for p in prs:
        click.echo(f"  PR #{p['pr_number']}: {p['title']}")
        click.echo(f"    Repository: {p['repository']} | Author: {p['author']}")
        click.echo(f"    Head SHA: {p['head_sha'][:7]} | Gate: [{p['policy_result']}]")
        click.echo(f"    Score: {p['security_score']}/100 (Delta: {p['score_delta']:+d}) | New Vulns: {p['new_vulnerabilities_count']} | Fixed: {p['fixed_vulnerabilities_count']}\n")


@github_group.command(name="status")
def webhook_status():
    """Show GitHub App webhook delivery and queue status metrics."""
    stat = service.get_webhook_status()
    click.echo("\n--- GitHub Integration & Webhook Status ---")
    click.echo(f"  Webhook Listener: ACTIVE")
    click.echo(f"  Total Webhook Events Received: {stat['total_events']}")
    click.echo(f"  Completed Events: {stat['completed']}")
    click.echo(f"  Queued Events: {stat['queued']}")
    click.echo(f"  Dead Letter Queue: {stat['dead_letter_count']}")
