"""CLI subcommands (scan, project, dependencies, secrets, git, sbom, report, rules, plugins, config, version)."""

from python_hunter.interfaces.cli.commands.sbom import run_sbom_command

__all__ = ["run_sbom_command"]
