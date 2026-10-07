"""CLI commands for the Security Intelligence Engine: sources, posture, remediation, and trends."""

import argparse

from rich.console import Console
from rich.table import Table

from python_hunter.application.services.security_app_service import SecurityApplicationService

console = Console()


def register_intelligence_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'intelligence', 'posture', 'remediation', and 'trends' commands."""
    intel = subparsers.add_parser("intelligence", help="Security Intelligence Engine sources and updates")
    intel_sub = intel.add_subparsers(dest="intelligence_action")
    intel_sub.add_parser("status", help="Display active intelligence sources and freshness state")
    intel_sub.add_parser("update", help="Update local intelligence database")

    subparsers.add_parser("posture", help="Display current Security Posture & SLA status")
    subparsers.add_parser("remediation", help="Display prioritized Remediation Work Queue")
    subparsers.add_parser("trends", help="Display Security Trending and MTTR metrics")


def run_intelligence_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    if (getattr(args, "intelligence_action", None) or "status") == "update":
        recs = service.intel_engine.ingest_intelligence()
        service.intel_db.save_records(recs)
        console.print(
            f"[bold green]Successfully updated intelligence database with {len(recs)} canonical vulnerability records.[/bold green]"
        )
        return 0

    table = Table(title="Security Intelligence Sources & Freshness")
    table.add_column("Source", style="cyan")
    table.add_column("Enabled", style="bold")
    table.add_column("Trust Level", style="magenta")
    table.add_column("Freshness State", style="yellow")
    table.add_column("Version", style="green")
    for name, info in service.intel_registry.status().items():
        table.add_row(
            name,
            "Yes" if info["enabled"] else "No",
            info["trust_level"],
            info["freshness"],
            info["version"],
        )
    console.print(table)
    return 0


def run_posture_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    snap = service.posture_tracker.capture_posture(service.remediation_queue.get_ranked_queue())

    table = Table(title="Security Posture Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold yellow")
    table.add_row("Security Score", f"{snap.security_score} / 100")
    table.add_row("Current Risk Score", str(snap.current_risk_score))
    table.add_row("Critical Vulnerabilities", str(snap.critical_vulnerabilities_count))
    table.add_row("High Vulnerabilities", str(snap.high_vulnerabilities_count))
    table.add_row("Overdue SLA Breaches", str(snap.overdue_sla_count))
    table.add_row("Verified Findings", str(snap.verified_vulnerabilities_count))
    console.print(table)
    return 0


def run_remediation_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    table = Table(title="Prioritized Remediation Queue")
    table.add_column("Rank Score", style="bold magenta")
    table.add_column("Vulnerability ID", style="cyan")
    table.add_column("Repository", style="green")
    table.add_column("Severity", style="bold red")
    table.add_column("Reachable", style="yellow")
    table.add_column("Verified", style="blue")
    table.add_column("SLA Overdue", style="bold red")
    for i in service.remediation_queue.get_ranked_queue():
        table.add_row(
            str(i.rank_score),
            i.vulnerability_id,
            i.repository,
            i.severity.value,
            "Yes" if i.is_reachable else "No",
            "Yes" if i.is_verified else "No",
            "YES" if i.is_overdue else "No",
        )
    console.print(table)
    return 0


def run_trends_command(args: argparse.Namespace) -> int:
    service = SecurityApplicationService()
    mttr = service.remediation_queue.calculate_mttr()
    table = Table(title="Security Trending & MTTR Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold green")
    table.add_row("Overall MTTR (Days)", str(mttr["overall_days"]))
    table.add_row("Critical MTTR (Days)", str(mttr["critical_days"]))
    console.print(table)
    return 0
