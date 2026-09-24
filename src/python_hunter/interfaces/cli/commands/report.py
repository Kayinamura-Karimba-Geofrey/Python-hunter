"""CLI Command Handler for Executive Security Report Generation."""

import argparse
import os
import sys

from python_hunter.application.use_cases.generate_report import GenerateReportUseCase


def run_report_command(args: list[str]) -> int:
    """Execute python-hunter report command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter report",
        description="Generate executive, compliance, and developer security reports in HTML, Markdown, or JSON.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or manifest file to audit (default: .)",
    )
    parser.add_argument(
        "--type",
        choices=["executive", "compliance", "technical"],
        default="executive",
        help="Report archetype (default: executive)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "markdown", "md", "json"],
        default="html",
        help="Report export format (default: html)",
    )
    parser.add_argument(
        "--framework",
        default="owasp-top-10",
        help="Compliance framework benchmark (e.g. owasp-top-10, nist, soc-2, iso27001, cis)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: python-hunter-report.html or stdout)",
    )
    parser.add_argument(
        "--organization",
        default="Enterprise Security",
        help="Organization or team name to appear on report header",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Custom report title",
    )

    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    try:
        use_case = GenerateReportUseCase()
        res = use_case.execute(
            target_path=parsed_args.target,
            report_type=parsed_args.type,
            format_type=parsed_args.format,
            framework_id=parsed_args.framework,
            organization=parsed_args.organization,
            title=parsed_args.title,
        )

        out_path = parsed_args.output
        if not out_path and parsed_args.format == "html" and sys.stdout.isatty():
            out_path = "python-hunter-report.html"

        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(res["content"] + "\n")
            sys.stdout.write(
                f"[✓] {res['report_type'].capitalize()} Security Report generated ({res['findings_count']} findings, Grade {res['compliance_grade']}) -> {out_path}\n"
            )
        else:
            sys.stdout.write(res["content"] + "\n")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error generating security report: {e}\n")
        return 1
