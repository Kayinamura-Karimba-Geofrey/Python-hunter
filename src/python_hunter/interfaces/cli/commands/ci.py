"""CLI Subcommand: ci."""

import argparse
import sys

from python_hunter.application.use_cases.run_ci import RunCIUseCase


def run_ci_command(args: argparse.Namespace) -> int:
    """Execute CI security pipeline execution flow."""
    use_case = RunCIUseCase()
    opts = {
        "quiet": getattr(args, "quiet", False),
        "verbose": getattr(args, "verbose", False),
        "redact_secrets": not getattr(args, "no_redact", False),
    }
    return use_case.execute(
        target_path=args.target,
        export_artifacts=not getattr(args, "no_artifacts", False),
        output_dir=getattr(args, "output_dir", "."),
        options=opts,
    )
