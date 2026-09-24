"""CLI Command Handler for Language Server Protocol (python-hunter lsp)."""

import argparse
import logging
import sys

from python_hunter.interfaces.lsp.server import LSPServer


def run_lsp_command(args: list[str]) -> int:
    """Execute python-hunter lsp command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter lsp",
        description="Run Python Hunter Language Server Protocol (LSP 3.17) server for real-time IDE diagnostics.",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Run language server over standard input and output (default, used by VS Code / Neovim)",
    )
    parser.add_argument(
        "--tcp",
        metavar="[HOST:]PORT",
        default="",
        help="Listen for LSP client connections over TCP (e.g. 2087 or 127.0.0.1:2087)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        default="",
        help="Log server operations and JSON-RPC wire messages to the specified file",
    )

    parsed = parser.parse_args(args)

    if parsed.log_file:
        logging.basicConfig(
            filename=parsed.log_file,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    server = LSPServer()

    if parsed.tcp:
        host = "127.0.0.1"
        port_str = parsed.tcp
        if ":" in parsed.tcp:
            host, port_str = parsed.tcp.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            sys.stderr.write(f"Error: Invalid TCP port specification '{parsed.tcp}'. Expected integer or host:port.\n")
            return 1

        sys.stderr.write(f"Python Hunter LSP server listening on tcp://{host}:{port}...\n")
        server.serve_tcp(host=host, port=port)
        return 0

    # Default to stdio
    server.serve_stdio()
    return 0
