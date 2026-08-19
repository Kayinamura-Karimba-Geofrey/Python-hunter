"""Main Professional CLI Entry Point for Python Hunter."""

import sys
import click

from python_hunter import __version__
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.presentation.policy import ExitCode, PolicyEngine
from python_hunter.presentation.renderer import JsonRenderer, TerminalRenderer


@click.group()
@click.version_option(version=__version__, prog_name="python-hunter")
def main() -> None:
    """Python Hunter - Professional Security & Code Intelligence Platform."""
    pass


@main.command()
@click.argument("target", default=".")
@click.option("--branch", default="", help="Git branch to clone/scan.")
@click.option("--commit", default="", help="Specific Git commit SHA to checkout and scan.")
@click.option("--tag", default="", help="Git tag to checkout and scan.")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]), default="terminal", help="Output format.")
@click.option("--output", "out_file", default="", help="Output file path.")
@click.option("--fail-on", default="high", help="Severity threshold to trigger non-zero exit code (critical, high, medium, low).")
def scan(target: str, branch: str, commit: str, tag: str, fmt: str, out_file: str, fail_on: str) -> None:
    """Scans local project directories, files, or remote GitHub repositories."""
    orchestrator = ScanOrchestrator()
    policy_engine = PolicyEngine()

    try:
        result = orchestrator.run_scan(target, branch=branch, commit=commit, tag=tag, fail_on=fail_on)
        exit_code = policy_engine.evaluate(result, fail_on=fail_on)
        result.exit_code = exit_code

        renderer = JsonRenderer() if fmt == "json" else TerminalRenderer()
        output_str = renderer.render(result)

        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output_str)
            click.echo(f"Report written to '{out_file}'.")
        else:
            click.echo(output_str)

        sys.exit(exit_code)

    except Exception as e:
        click.echo(f"[!] Scan Error: {e}", err=True)
        sys.exit(ExitCode.TARGET_REPO_ERROR)


@main.command()
@click.argument("target", default=".")
def graph(target: str) -> None:
    """Builds and inspects the Whole-Project Security Knowledge Graph."""
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(target)
    nodes_count = len(result.graph.nodes) if result.graph else 0
    edges_count = len(result.graph.edges) if result.graph else 0
    click.echo(f"Security Knowledge Graph built successfully: {nodes_count} nodes, {edges_count} edges.")


@main.command()
@click.argument("target", default=".")
def attack_paths(target: str) -> None:
    """Reconstructs and displays end-to-end multi-vulnerability attack paths."""
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(target)
    click.echo(f"Reconstructed {len(result.attack_paths)} attack paths.")


if __name__ == "__main__":
    main()
