"""CLI commands for Security Operations: monitoring, alerts, incidents, jobs, and health."""

import argparse

from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.operations.scheduler import MonitoredRepository

console = Console()


def register_operations_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'monitor', 'alerts', 'incidents', 'jobs', and 'health' commands."""
    monitor = subparsers.add_parser("monitor", help="Continuous security monitoring management")
    monitor_sub = monitor.add_subparsers(dest="monitor_action")
    monitor_sub.add_parser("status", help="Display monitored repositories and scanning state")
    start = monitor_sub.add_parser("start", help="Start continuous monitoring on a repository")
    start.add_argument("repository", nargs="?", default="local/workspace")
    stop = monitor_sub.add_parser("stop", help="Pause continuous monitoring on a repository")
    stop.add_argument("repository", nargs="?", default="local/workspace")

    subparsers.add_parser("alerts", help="Display open security alerts")
    subparsers.add_parser("incidents", help="Display correlated security incidents")
    subparsers.add_parser("jobs", help="Display security job queue status")
    subparsers.add_parser("health", help="Display security platform health and telemetry")


def run_monitor_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    action = getattr(args, "monitor_action", None) or "status"

    if action == "start":
        service.scheduler.register_repository(MonitoredRepository(repository=args.repository))
        service.scheduler.resume_monitoring(args.repository)
        console.print(f"[bold green]Continuous security monitoring STARTED for {args.repository}.[/bold green]")
        return 0
    if action == "stop":
        if not service.scheduler.pause_monitoring(args.repository):
            console.print(f"[bold red]{args.repository} is not being monitored.[/bold red]")
            return 1
        console.print(f"[bold yellow]Continuous security monitoring PAUSED for {args.repository}.[/bold yellow]")
        return 0

    table = Table(title="Continuous Security Monitoring Repositories")
    table.add_column("Repository", style="cyan")
    table.add_column("Branch", style="magenta")
    table.add_column("Mode", style="yellow")
    table.add_column("Frequency (min)", style="green")
    table.add_column("Status", style="bold blue")
    for repo in service.scheduler.monitored_repos.values():
        table.add_row(
            repo.repository,
            repo.branch,
            repo.monitoring_mode.value,
            str(repo.scan_frequency_minutes),
            "PAUSED" if repo.is_paused else "ACTIVE",
        )
    console.print(table)
    return 0


def run_alerts_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    table = Table(title="Security Operations Alerts")
    table.add_column("Alert ID", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Type", style="yellow")
    table.add_column("Repository", style="green")
    table.add_column("Title", style="bold")
    table.add_column("Status", style="magenta")
    for a in service.alert_engine.get_open_alerts():
        table.add_row(a.alert_id, a.severity.value, a.alert_type.value, a.repository, a.title, a.status.value)
    console.print(table)
    return 0


def run_incidents_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    incidents = service.incident_engine.correlate_alerts(service.alert_engine.get_open_alerts())
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
    return 0


def run_jobs_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    table = Table(title="Security Operations Job Queue")
    table.add_column("Job ID", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Repository", style="green")
    table.add_column("Priority", style="magenta")
    table.add_column("Status", style="bold blue")
    for j in service.job_queue.list_all():
        table.add_row(j.job_id, j.job_type.value, j.repository, str(j.priority), j.status.value)
    console.print(table)
    return 0


def run_health_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    table = Table(title="Security Platform Health & Telemetry")
    table.add_column("Component / Metric", style="cyan")
    table.add_column("Status / Value", style="bold green")
    for k, v in service.health_monitor.to_dict().items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)
    return 0
