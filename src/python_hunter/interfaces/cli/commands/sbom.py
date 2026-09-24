"""CLI Command Handler for Software Bill of Materials (SBOM) Generation."""

import argparse
import sys
from python_hunter.application.use_cases.generate_sbom import GenerateSBOMUseCase


def run_sbom_command(args: list[str]) -> int:
    """Execute python-hunter sbom command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter sbom",
        description="Generate CycloneDX 1.5 or SPDX 2.3 Software Bill of Materials (SBOM).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or manifest file (default: .)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["cyclonedx", "cdx", "spdx", "spdx-json"],
        default="cyclonedx",
        help="SBOM standard format (default: cyclonedx)",
    )
    parser.add_argument(
        "--spec-version",
        default=None,
        help="Specification version (e.g. 1.5, 1.4 for CycloneDX; 2.3, 2.2 for SPDX)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: write to standard output)",
    )
    parser.add_argument(
        "--include-vulns",
        action="store_true",
        help="Embed vulnerability findings into CycloneDX SBOM document",
    )

    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    try:
        use_case = GenerateSBOMUseCase()
        result = use_case.execute(
            target_path=parsed_args.target,
            format_type=parsed_args.format,
            spec_version=parsed_args.spec_version,
            include_vulns=parsed_args.include_vulns,
        )

        sbom_output = result["sbom_json"]

        if parsed_args.output:
            with open(parsed_args.output, "w", encoding="utf-8") as f:
                f.write(sbom_output + "\n")
            fmt_display = result["format"].upper()
            sys.stdout.write(
                f"[✓] {fmt_display} SBOM generated successfully ({result['components_count']} components) -> {parsed_args.output}\n"
            )
        else:
            sys.stdout.write(sbom_output + "\n")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error generating SBOM: {e}\n")
        return 1
