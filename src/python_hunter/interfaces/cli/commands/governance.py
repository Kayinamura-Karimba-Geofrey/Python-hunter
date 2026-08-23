"""CLI Commands for Step 42 Enterprise Multi-Tenancy & Security Governance."""

import click
from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.governance.tenant import Organization

console = Console()
service = SecurityApplicationService()


@click.group()
def org() -> None:
    """Enterprise Organization & Governance management commands."""
    pass


@org.command(name="list")
def org_list() -> None:
    """Display registered multi-tenant Organizations."""
    table = Table(title="Enterprise Organizations")
    table.add_column("Org ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Slug", style="yellow")
    table.add_column("Status", style="bold green")

    for o in service.organizations.values():
        table.add_row(o.organization_id, o.name, o.slug, o.status.value)

    console.print(table)


@org.command(name="users")
def org_users() -> None:
    """Display Organization Users."""
    table = Table(title="Organization Users")
    table.add_column("User ID", style="cyan")
    table.add_column("Email", style="green")
    table.add_column("Display Name", style="bold")
    table.add_column("Status", style="magenta")

    for u in service.users.values():
        table.add_row(u.user_id, u.email, u.display_name, u.status.value)

    console.print(table)


@org.command(name="teams")
def org_teams() -> None:
    """Display Organization Teams."""
    table = Table(title="Organization Teams")
    table.add_column("Team ID", style="cyan")
    table.add_column("Organization", style="yellow")
    table.add_column("Name", style="bold green")

    for t in service.teams.values():
        table.add_row(t.team_id, t.organization_id, t.name)

    console.print(table)


@org.command(name="projects")
def org_projects() -> None:
    """Display Organization Projects."""
    table = Table(title="Organization Projects & Environment Classification")
    table.add_column("Project ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Owner Team", style="green")
    table.add_column("Environment", style="yellow")
    table.add_column("Criticality", style="bold red")

    for p in service.projects.values():
        table.add_row(p.project_id, p.name, p.owner_team_id, p.environment.value, p.criticality.value)

    console.print(table)


@org.command(name="approvals")
def org_approvals() -> None:
    """Display Pending Security Approvals (Four-Eyes Principle)."""
    table = Table(title="Security Approvals Governance Queue")
    table.add_column("Approval ID", style="cyan")
    table.add_column("Action Type", style="yellow")
    table.add_column("Requester", style="green")
    table.add_column("Approver", style="magenta")
    table.add_column("Status", style="bold blue")

    for a in service.governance_engine.approvals.values():
        table.add_row(
            a.approval_id,
            a.action_type,
            a.requester_user_id,
            a.approver_user_id or "Pending",
            a.status.value,
        )

    console.print(table)
