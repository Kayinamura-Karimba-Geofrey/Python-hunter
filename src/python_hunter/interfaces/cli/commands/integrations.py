"""CLI Commands for Step 43 Enterprise Integrations & Security Ecosystem."""

import click
from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.integrations.models import IntegrationProviderType

console = Console()
service = SecurityApplicationService()


@click.group()
def integrations() -> None:
    """Enterprise Integrations & Security Ecosystem commands."""
    pass


@integrations.command(name="list")
def integrations_list() -> None:
    """Display registered enterprise integrations."""
    table = Table(title="Enterprise Integrations Ecosystem")
    table.add_column("Integration ID", style="cyan")
    table.add_column("Organization", style="yellow")
    table.add_column("Provider", style="magenta")
    table.add_column("Name", style="bold green")
    table.add_column("Status", style="bold blue")

    for i in service.integration_engine.integrations.values():
        table.add_row(i.integration_id, i.organization_id, i.provider.value, i.name, i.status.value)

    console.print(table)


@integrations.command(name="status")
def integrations_status() -> None:
    """Display health and circuit breaker status of integrations."""
    table = Table(title="Integrations Health & Circuit Breaker Telemetry")
    table.add_column("Integration ID", style="cyan")
    table.add_column("Provider", style="magenta")
    table.add_column("Circuit Breaker State", style="bold green")
    table.add_column("Failure Count", style="bold red")

    for i_id, cb in service.integration_engine.circuit_breakers.items():
        integ = service.integration_engine.integrations.get(i_id)
        provider_val = integ.provider.value if integ else "unknown"
        table.add_row(i_id, provider_val, cb.state, str(cb.failure_count))

    console.print(table)


@integrations.command(name="test")
@click.argument("integration_id", default="int-github-default")
def integrations_test(integration_id: str) -> None:
    """Test connection to target integration provider."""
    integ = service.integration_engine.integrations.get(integration_id)
    if not integ:
        console.print(f"[bold red]Integration {integration_id} not found.[/bold red]")
        return

    provider = service.integration_engine.registry.get(integ.provider)
    if not provider:
        console.print(f"[bold red]Provider for {integ.provider.value} not registered.[/bold red]")
        return

    healthy = provider.health_check()
    console.print(f"[bold green]Integration {integration_id} ({integ.provider.value}) test: {healthy.value}[/bold green]")
