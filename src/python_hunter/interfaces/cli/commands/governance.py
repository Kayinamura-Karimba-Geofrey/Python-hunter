"""CLI commands for Enterprise Multi-Tenancy & Security Governance."""

import argparse

from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService

console = Console()


def register_org_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'org' command group."""
    org = subparsers.add_parser("org", help="Enterprise organization and governance management")
    org_sub = org.add_subparsers(dest="org_action")
    org_sub.add_parser("list", help="Display registered organizations")
    org_sub.add_parser("users", help="Display organization users")
    org_sub.add_parser("teams", help="Display organization teams")
    org_sub.add_parser("projects", help="Display organization projects")
    org_sub.add_parser("approvals", help="Display pending security approvals")


def run_org_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    action = getattr(args, "org_action", None) or "list"

    if action == "users":
        table = Table(title="Organization Users")
        table.add_column("User ID", style="cyan")
        table.add_column("Email", style="green")
        table.add_column("Display Name", style="bold")
        table.add_column("Status", style="magenta")
        for u in service.users.values():
            table.add_row(u.user_id, u.email, u.display_name, u.status.value)
    elif action == "teams":
        table = Table(title="Organization Teams")
        table.add_column("Team ID", style="cyan")
        table.add_column("Organization", style="yellow")
        table.add_column("Name", style="bold green")
        for t in service.teams.values():
            table.add_row(t.team_id, t.organization_id, t.name)
    elif action == "projects":
        table = Table(title="Organization Projects & Environment Classification")
        table.add_column("Project ID", style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Owner Team", style="green")
        table.add_column("Environment", style="yellow")
        table.add_column("Criticality", style="bold red")
        for p in service.projects.values():
            table.add_row(p.project_id, p.name, p.owner_team_id, p.environment.value, p.criticality.value)
    elif action == "approvals":
        table = Table(title="Security Approvals Governance Queue")
        table.add_column("Approval ID", style="cyan")
        table.add_column("Action Type", style="yellow")
        table.add_column("Requester", style="green")
        table.add_column("Approver", style="magenta")
        table.add_column("Status", style="bold blue")
        for a in service.governance_engine.approvals.values():
            table.add_row(
                a.approval_id, a.action_type, a.requester_user_id, a.approver_user_id or "Pending", a.status.value
            )
    else:
        table = Table(title="Enterprise Organizations")
        table.add_column("Org ID", style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Slug", style="yellow")
        table.add_column("Status", style="bold green")
        for o in service.organizations.values():
            table.add_row(o.organization_id, o.name, o.slug, o.status.value)

    console.print(table)
    return 0
