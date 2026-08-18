"""CLI Command handler for Security Analysis."""

import argparse
import sys
from typing import Any

from python_hunter.application.use_cases.generate_report import GenerateReportUseCase


def run_analyze_command(args: argparse.Namespace) -> int:
    """Execute analyze CLI command using GenerateReportUseCase."""
    try:
        use_case = GenerateReportUseCase()

        target_path = getattr(args, "target", ".")
        fmt = getattr(args, "format", "terminal")
        out_file = getattr(args, "output", None)

        opts = {
            "quiet": getattr(args, "quiet", False),
            "verbose": getattr(args, "verbose", False),
            "details": getattr(args, "details", False),
            "redact_secrets": not getattr(args, "no_redact", False),
        }

        output_content = use_case.execute(
            target_path=target_path,
            format_name=fmt,
            severity=getattr(args, "severity", None),
            category=getattr(args, "category", None),
            component=getattr(args, "component", None),
            status=getattr(args, "status", None),
            confidence=getattr(args, "confidence", None),
            sort_by=getattr(args, "sort", "risk"),
            limit=getattr(args, "limit", None),
            options=opts,
        )

        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output_content + "\n")
        else:
            sys.stdout.write(output_content + "\n")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error during security analysis: {e}\n")
        return 1
