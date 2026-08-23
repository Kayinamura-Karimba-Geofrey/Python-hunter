"""CLI Commands for Step 41 Autonomous Security Operations & Continuous Monitoring."""

import click
from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.operations.alerts import AlertType
from python_hunter.domain.operations.scheduler import MonitoredRepository

console = Console()
service = SecurityApplicationService()


@click.group()
def monitor() -> None:
    """Continuous Security Monitoring management commands."""
    pass


@monitor.command(name="status")
def monitor_status() -> None:
    """Display active monitored repositories and continuous scanning state."""
    table = Table(title="Continuous Security Monitoring Repositories")
    table.add_column("Repository", style="cyan")
    table.add_column("Branch", style="magenta")
    table.add_column("Mode", style="yellow")
    table.add_column("Frequency (min)", style="green")
    table.add_column("Status", style="bold blue")

    # Add default workspace if empty
    if not service.scheduler.monitored_repos:
        service.scheduler.register_repository(
            MonitoredRepository(repository="local/workspace", branch="main")
        )

    for repo in service.scheduler.monitored_repos.values():
        table.add_row(
            repo.repository,
            repo.branch,
            repo.monitoring_mode.value,
            str(repo.scan_frequency_minutes),
            "PAUSED" if repo.is_paused else "ACTIVE",
        )

    console.print(table)


@monitor.command(name="start")
@click.argument("repository", default="local/workspace")
def monitor_start(repository: str) -> None:
    """Start continuous monitoring on target repository."""
    service.scheduler.register_repository(MonitoredRepository(repository=repository))
    service.scheduler.resume_monitoring(repository)
    console.print(f"[bold green]Continuous security monitoring STARTED for {repository}.[/bold green]")


@monitor.command(name="stop")
@click.argument("repository", default="local/workspace")
def monitor_stop(repository: str) -> None:
    """Stop/pause continuous monitoring on target repository."""
    service.scheduler.pause_monitoring(repository)
    console.print(f"[bold yellow]Continuous security monitoring PAUSED for {repository}.[/bold yellow]")


@click.command(name="alerts")
def alerts_command() -> None:
    """Display Security Alerts."""
    # Seed mock alert if empty for demo
    if not service.alert_engine.alerts:
        service.alert_engine.create_or_deduplicate_alert(
            alert_id="ALT-101",
            severity=Severity.CRITICAL,
            alert_type=AlertType.CRITICAL_VULNERABILITY,
            source="IntelligenceEngine",
            repository="kayinamura-karimba-geofrey/python-hunter",
            title="CVE-2023-32681 High Vulnerability Detected",
            description="Leaked proxy authentication credentials vulnerability.",
            finding_id="FIND-99",
        )

    open_alerts = service.alert_engine.get_open_alerts()
    table = Table(title="Security Operations Alerts")
    table.add_column("Alert ID", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Type", style="yellow")
    table.add_column("Repository", style="green")
    table.add_column("Title", style="bold")
    table.add_column("Status", style="magenta")

    for a in open_alerts:
        table.add_row(
            a.alert_id,
            a.severity.value,
            a.alert_type.value,
            a.repository,
            a.title,
            a.status.value,
        )

    console.print(table)


@click.command(name="incidents")
def incidents_command() -> None:
    """Display Correlated Security Incidents."""
    alerts = service.alert_engine.get_open_alerts()
    incidents = service.incident_engine.correlate_alerts(alerts)

    table = Table(title="Security Operations Incidents")
    table.add_column("Incident ID", style="bold cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Repository", style="green")
    table.add_column("Correlated Alerts", style="yellow")
    table.add_column("Status", style="magenta")

    for inc in incidents:
        table.add_row(
            inc.incident_id,
            inc.severity.value,
            ", ".join(inc.affected_repositories),
            str(len(inc.alerts)),
            inc.status.value,
        )

    console.print(table)


@click.command(name="jobs")
def jobs_command() -> None:
    """Display Security Job Queue Status."""
    jobs = service.job_queue.list_all()
    table = Table(title="Security Operations Job Queue")
    table.add_column("Job ID", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Repository", style="green")
    table.add_column("Priority", style="magenta")
    table.add_column("Status", style="bold blue")

    for j in jobs:
        table.add_row(
            j.job_id,
            j.job_type.value,
            j.repository,
            str(j.priority),
            j.status.value,
        )

    console.print(table)


@click.command(name="health")
def health_command() -> None:
    """Display Security Platform Health & Telemetry."""
    st = service.health_monitor.to_dict()
    table = Table(title="Security Platform Health & Telemetry")
    table.add_column("Component / Metric", style="cyan")
    table.add_column("Status / Value", style="bold green")

    for k, v in st.items():
        table.add_row(k.replace("_", " ").title(), str(v))

    console.print(table)
