"""LSP Language Server Implementation for Python Hunter.

Provides real-time in-editor security diagnostics, CodeActions, and workspace commands
over standard input/output (stdio) or TCP sockets for VS Code, JetBrains, Neovim, and Sublime Text.
"""

import json
import logging
import os
import socket
import sys
import threading
from typing import Any, BinaryIO

from python_hunter.interfaces.lsp.analyzer import LSPSecurityAnalyzer
from python_hunter.interfaces.lsp.protocol import (
    TextDocumentSyncKind,
    make_error_response,
    make_notification,
    make_response,
    read_lsp_message,
    write_lsp_message,
)

logger = logging.getLogger(__name__)


class LSPServer:
    """Language Server Protocol 3.17 server for Python Hunter."""

    def __init__(self, analyzer: LSPSecurityAnalyzer | None = None) -> None:
        self.analyzer = analyzer or LSPSecurityAnalyzer()
        self.documents: dict[str, str] = {}
        self.is_running = False
        self._shutdown_received = False
        self.lock = threading.Lock()

    def handle_message(self, message: dict[str, Any], writer: BinaryIO) -> None:
        """Dispatches an incoming JSON-RPC 2.0 message."""
        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})

        # Notification handling (no id)
        if msg_id is None:
            self._handle_notification(method, params, writer)
            return

        # Request handling (has id)
        try:
            if method == "initialize":
                res = self._on_initialize(params)
                write_lsp_message(writer, make_response(msg_id, res))
            elif method == "shutdown":
                self._shutdown_received = True
                write_lsp_message(writer, make_response(msg_id, None))
            elif method == "textDocument/codeAction":
                res = self._on_code_action(params)
                write_lsp_message(writer, make_response(msg_id, res))
            elif method == "workspace/executeCommand":
                res = self._on_execute_command(params, writer)
                write_lsp_message(writer, make_response(msg_id, res))
            else:
                # Unsupported method
                write_lsp_message(
                    writer,
                    make_error_response(msg_id, -32601, f"Method not found: {method}"),
                )
        except Exception as e:
            logger.error(f"Error handling LSP request '{method}': {e}", exc_info=True)
            write_lsp_message(
                writer,
                make_error_response(msg_id, -32603, f"Internal server error: {e}"),
            )

    def _handle_notification(self, method: str, params: dict[str, Any], writer: BinaryIO) -> None:
        """Handles LSP notifications."""
        if method == "initialized":
            logger.info("Python Hunter LSP client initialized successfully.")
        elif method == "exit":
            self.is_running = False
        elif method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            text = doc.get("text", "")
            with self.lock:
                self.documents[uri] = text
            self._publish_diagnostics(uri, text, writer)
        elif method == "textDocument/didChange":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            changes = params.get("contentChanges", [])
            if changes:
                # Full sync: last change is complete text
                new_text = changes[-1].get("text", "")
                with self.lock:
                    self.documents[uri] = new_text
                self._publish_diagnostics(uri, new_text, writer)
        elif method == "textDocument/didSave":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            text = doc.get("text")
            if text is None:
                with self.lock:
                    text = self.documents.get(uri)
            self._publish_diagnostics(uri, text, writer)
        elif method == "textDocument/didClose":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            with self.lock:
                self.documents.pop(uri, None)

    def _on_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handles LSP 'initialize' request."""
        return {
            "capabilities": {
                "textDocumentSync": {
                    "openClose": True,
                    "change": int(TextDocumentSyncKind.FULL),
                    "save": {"includeText": True},
                },
                "codeActionProvider": True,
                "executeCommandProvider": {
                    "commands": [
                        "python-hunter.scanWorkspace",
                        "python-hunter.applyFix",
                    ]
                },
            },
            "serverInfo": {
                "name": "python-hunter-lsp",
                "version": "1.0.0",
            },
        }

    def _on_code_action(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Handles LSP 'textDocument/codeAction' request."""
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        range_dict = params.get("range", {})
        context = params.get("context", {})
        diagnostics = context.get("diagnostics", [])

        with self.lock:
            doc_text = self.documents.get(uri)

        return self.analyzer.generate_code_actions(
            uri=uri,
            range_dict=range_dict,
            diagnostics=diagnostics,
            document_text=doc_text,
        )

    def _on_execute_command(self, params: dict[str, Any], writer: BinaryIO) -> dict[str, Any]:
        """Handles LSP 'workspace/executeCommand' request."""
        command = params.get("command")
        args = params.get("arguments", [])

        if command == "python-hunter.applyFix" and args:
            uri = args[0]
            with self.lock:
                text = self.documents.get(uri)
            # Re-publish diagnostics after applying fix
            self._publish_diagnostics(uri, text, writer)
            return {"applied": True}

        return {"applied": False}

    def _publish_diagnostics(self, uri: str, content: str | None, writer: BinaryIO) -> None:
        """Analyzes document and dispatches 'textDocument/publishDiagnostics' notification."""
        try:
            diagnostics = self.analyzer.analyze_document(uri, content)
            notification = make_notification(
                "textDocument/publishDiagnostics",
                {
                    "uri": uri,
                    "diagnostics": diagnostics,
                },
            )
            write_lsp_message(writer, notification)
        except Exception as e:
            logger.error(f"Failed to publish diagnostics for '{uri}': {e}", exc_info=True)

    def serve_stdio(self, reader: BinaryIO | None = None, writer: BinaryIO | None = None) -> None:
        """Runs the LSP server loop over standard input and output."""
        reader = reader or sys.stdin.buffer
        writer = writer or sys.stdout.buffer
        self.is_running = True

        while self.is_running:
            try:
                msg = read_lsp_message(reader)
                if msg is None:
                    break
                self.handle_message(msg, writer)
            except Exception as e:
                logger.error(f"Unexpected error in LSP stdio loop: {e}", exc_info=True)
                break

    def serve_tcp(self, host: str = "127.0.0.1", port: int = 2087) -> None:
        """Runs the LSP server loop accepting connections over a TCP socket."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)
        self.is_running = True
        logger.info(f"Python Hunter LSP server listening on tcp://{host}:{port}")

        try:
            while self.is_running:
                client_sock, client_addr = server_sock.accept()
                thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock,),
                    daemon=True,
                )
                thread.start()
        finally:
            server_sock.close()

    def _handle_tcp_client(self, client_sock: socket.socket) -> None:
        """Handles an individual TCP client connection."""
        reader = client_sock.makefile("rb")
        writer = client_sock.makefile("wb")
        try:
            while self.is_running:
                msg = read_lsp_message(reader)
                if msg is None:
                    break
                self.handle_message(msg, writer)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
