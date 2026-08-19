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
@click.option("--ci", is_flag=True, help="Enable CI-friendly deterministic non-interactive execution mode.")
@click.option("--scan-mode", type=click.Choice(["full", "pull-request"]), default="full", help="Scan mode (full or pull-request).")
@click.option("--min-confidence", default="medium", help="Minimum confidence threshold (high, medium, low).")
@click.option("--baseline", default="", help="Path to baseline file for differential PR scan.")
@click.option("--require-exploitable", is_flag=True, help="Only fail build on provably exploitable findings.")
def scan(
    target: str,
    branch: str,
    commit: str,
    tag: str,
    fmt: str,
    out_file: str,
    fail_on: str,
    ci: bool,
    scan_mode: str,
    min_confidence: str,
    baseline: str,
    require_exploitable: bool,
) -> None:
    """Scans local project directories, files, or remote GitHub repositories."""
    orchestrator = ScanOrchestrator()
    policy_engine = PolicyEngine()

    options = {
        "is_ci": ci,
        "scan_mode": scan_mode,
        "min_confidence": min_confidence,
        "baseline": baseline,
        "require_exploitable": require_exploitable,
    }

    try:
        result = orchestrator.run_scan(target, branch=branch, commit=commit, tag=tag, fail_on=fail_on, options=options)
        exit_code = policy_engine.evaluate(result, fail_on=fail_on)
        result.exit_code = exit_code

        if fmt == "json":
            renderer = JsonRenderer()
            output_str = renderer.render(result)
        elif fmt == "sarif":
            output_str = """{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Python Hunter",
          "informationUri": "https://github.com/Kayinamura-Karimba-Geofrey/Python-hunter",
          "rules": []
        }
      },
      "results": []
    }
  ]
}"""
        else:
            renderer = TerminalRenderer()
            output_str = renderer.render(result)

        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output_str)
            if not ci:
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
