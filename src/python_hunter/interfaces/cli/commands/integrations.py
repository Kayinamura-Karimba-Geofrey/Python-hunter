"""CLI commands for Enterprise Integrations & Security Ecosystem."""

import argparse

from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService

console = Console()


def register_integrations_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'integrations' command group."""
    integ = subparsers.add_parser("integrations", help="Enterprise integrations and ecosystem health")
    integ_sub = integ.add_subparsers(dest="integrations_action")
    integ_sub.add_parser("list", help="Display registered integrations")
    integ_sub.add_parser("status", help="Display integration health and circuit breaker state")
    test = integ_sub.add_parser("test", help="Test connection to an integration provider")
    test.add_argument("integration_id", nargs="?", default="int-github-default")


def run_integrations_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    engine = service.integration_engine
    action = getattr(args, "integrations_action", None) or "list"

    if action == "test":
        integ = engine.integrations.get(args.integration_id)
        if not integ:
            console.print(f"[bold red]Integration {args.integration_id} not found.[/bold red]")
            return 1
        provider = engine.registry.get(integ.provider)
        if not provider:
            console.print(f"[bold red]Provider for {integ.provider.value} not registered.[/bold red]")
            return 1
        healthy = provider.health_check()
        console.print(
            f"[bold green]Integration {args.integration_id} ({integ.provider.value}) test: {healthy.value}[/bold green]"
        )
        return 0

    if action == "status":
        table = Table(title="Integrations Health & Circuit Breaker Telemetry")
        table.add_column("Integration ID", style="cyan")
        table.add_column("Provider", style="magenta")
        table.add_column("Circuit Breaker State", style="bold green")
        table.add_column("Failure Count", style="bold red")
        for i_id, cb in engine.circuit_breakers.items():
            integ = engine.integrations.get(i_id)
            table.add_row(i_id, integ.provider.value if integ else "unknown", cb.state, str(cb.failure_count))
    else:
        table = Table(title="Enterprise Integrations Ecosystem")
        table.add_column("Integration ID", style="cyan")
        table.add_column("Organization", style="yellow")
        table.add_column("Provider", style="magenta")
        table.add_column("Name", style="bold green")
        table.add_column("Status", style="bold blue")
        for i in engine.integrations.values():
            table.add_row(i.integration_id, i.organization_id, i.provider.value, i.name, i.status.value)

    console.print(table)
    return 0
