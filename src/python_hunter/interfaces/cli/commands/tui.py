"""CLI Command Handler for Interactive Terminal TUI Dashboard."""

import argparse
import sys

from python_hunter.presentation.tui import SecurityTUI


def run_tui_command(args: list[str]) -> int:
    """Execute python-hunter tui command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter tui",
        description="Launch interactive terminal dashboard to inspect findings and attack paths.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory or repository (default: .)",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Print terminal dashboard snapshot and exit without launching curses UI",
    )

    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    try:
        tui = SecurityTUI(target_path=parsed_args.target)
        if parsed_args.snapshot or not sys.stdin.isatty():
            sys.stdout.write(tui.render_snapshot() + "\n")
            return 0
        return tui.run()
    except Exception as e:
        sys.stderr.write(f"Error launching TUI: {e}\n")
        return 1
