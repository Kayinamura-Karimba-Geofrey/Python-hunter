"""Unit tests for Python Hunter Language Server Protocol (LSP) and Diagnostics Engine."""

import io
import json
import os
import tempfile
import unittest

from python_hunter.interfaces.cli.commands.diagnostics import run_diagnostics_command
from python_hunter.interfaces.lsp.analyzer import LSPSecurityAnalyzer
from python_hunter.interfaces.lsp.protocol import (
    DiagnosticSeverity,
    path_to_uri,
    read_lsp_message,
    uri_to_path,
    write_lsp_message,
)
from python_hunter.interfaces.lsp.server import LSPServer


class TestLSPServerAndDiagnostics(unittest.TestCase):
    """Verifies LSP wire protocol, real-time analyzer, server lifecycle, and CLI diagnostics."""

    def setUp(self) -> None:
        self.analyzer = LSPSecurityAnalyzer()
        self.server = LSPServer(analyzer=self.analyzer)

    def test_uri_path_conversion(self) -> None:
        """Verify URI <-> Path conversions."""
        test_path = os.path.abspath("/tmp/project/app.py")
        uri = path_to_uri(test_path)
        self.assertTrue(uri.startswith("file://"))
        self.assertEqual(uri_to_path(uri), test_path)

    def test_message_framing_read_write(self) -> None:
        """Verify standard Content-Length JSON-RPC message framing."""
        stream = io.BytesIO()
        payload = {"jsonrpc": "2.0", "id": 1, "method": "testMethod", "params": {"key": "val"}}
        write_lsp_message(stream, payload)

        stream.seek(0)
        parsed = read_lsp_message(stream)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["id"], 1)
        self.assertEqual(parsed["method"], "testMethod")
        self.assertEqual(parsed["params"]["key"], "val")

    def test_python_sast_and_secrets_diagnostics(self) -> None:
        """Verify SAST and secret diagnostics on Python source code."""
        code = (
            "import os\n"
            "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "def handle_query(query):\n"
            "    eval(query)\n"
        )
        uri = "file:///tmp/vuln_app.py"
        diagnostics = self.analyzer.analyze_document(uri, content=code)

        self.assertGreaterEqual(len(diagnostics), 1)
        codes = [d["code"] for d in diagnostics]
        # Should detect eval (PYH-AST-001) or hardcoded credentials
        self.assertTrue(any("PYH-AST" in c or "PYH-SEC" in c for c in codes))
        # Ensure diagnostics have valid 0-indexed ranges and severity
        for d in diagnostics:
            self.assertIn("range", d)
            self.assertIn("start", d["range"])
            self.assertIn("line", d["range"]["start"])
            self.assertIn("severity", d)
            self.assertIn(d["severity"], (1, 2, 3, 4))
            self.assertEqual(d["source"], "python-hunter")

    def test_requirements_diagnostics(self) -> None:
        """Verify dependency diagnostics on requirements.txt."""
        reqs = (
            "requests<2.31.0\n"
            "urllib3\n"
            "flask==3.0.0\n"
        )
        uri = "file:///tmp/requirements.txt"
        diagnostics = self.analyzer.analyze_document(uri, content=reqs)

        self.assertGreaterEqual(len(diagnostics), 2)
        codes = [d["code"] for d in diagnostics]
        self.assertIn("PYH-DEP-001", codes)  # Unpinned urllib3
        self.assertIn("PYH-DEP-002", codes)  # Vulnerable requests

        # Verify line positions (0-indexed)
        unpinned = next(d for d in diagnostics if d["code"] == "PYH-DEP-001" and "urllib3" in d["message"])
        self.assertEqual(unpinned["range"]["start"]["line"], 1)  # line 2 (urllib3)

        vuln = next(d for d in diagnostics if d["code"] == "PYH-DEP-002")
        self.assertEqual(vuln["range"]["start"]["line"], 0)  # line 1 (requests)

    def test_package_json_diagnostics(self) -> None:
        """Verify NPM dependency diagnostics on package.json."""
        pkg_json = json.dumps(
            {
                "name": "frontend",
                "dependencies": {
                    "flatmap-stream": "0.1.1",
                    "express": "*",
                },
            },
            indent=2,
        )
        uri = "file:///tmp/package.json"
        diagnostics = self.analyzer.analyze_document(uri, content=pkg_json)

        codes = [d["code"] for d in diagnostics]
        self.assertIn("PYH-DEP-004", codes)  # Compromised / malicious flatmap-stream
        self.assertIn("PYH-DEP-001", codes)  # Unpinned express (*)

    def test_server_jsonrpc_lifecycle(self) -> None:
        """Verify LSP server JSON-RPC lifecycle: initialize, didOpen, codeAction, shutdown."""
        writer = io.BytesIO()

        # 1. Initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}},
        }
        self.server.handle_message(init_req, writer)
        writer.seek(0)
        init_resp = read_lsp_message(writer)
        self.assertIsNotNone(init_resp)
        self.assertEqual(init_resp["id"], 1)
        self.assertIn("capabilities", init_resp["result"])
        self.assertTrue(init_resp["result"]["capabilities"]["codeActionProvider"])

        # 2. didOpen notification
        writer = io.BytesIO()
        test_code = "eval('malicious_input()')\n"
        doc_uri = "file:///tmp/sample.py"
        open_notif = {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": doc_uri,
                    "languageId": "python",
                    "version": 1,
                    "text": test_code,
                }
            },
        }
        self.server.handle_message(open_notif, writer)
        writer.seek(0)
        diag_notif = read_lsp_message(writer)
        self.assertIsNotNone(diag_notif)
        self.assertEqual(diag_notif["method"], "textDocument/publishDiagnostics")
        self.assertEqual(diag_notif["params"]["uri"], doc_uri)
        diags = diag_notif["params"]["diagnostics"]
        self.assertGreaterEqual(len(diags), 1)

        # 3. codeAction request
        writer = io.BytesIO()
        action_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {"uri": doc_uri},
                "range": diags[0]["range"],
                "context": {"diagnostics": diags},
            },
        }
        self.server.handle_message(action_req, writer)
        writer.seek(0)
        action_resp = read_lsp_message(writer)
        self.assertIsNotNone(action_resp)
        self.assertEqual(action_resp["id"], 2)
        actions = action_resp["result"]
        self.assertGreaterEqual(len(actions), 1)
        self.assertTrue(any("python-hunter" in a["title"] for a in actions))

        # 4. shutdown request
        writer = io.BytesIO()
        shutdown_req = {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}}
        self.server.handle_message(shutdown_req, writer)
        writer.seek(0)
        shutdown_resp = read_lsp_message(writer)
        self.assertIsNotNone(shutdown_resp)
        self.assertIsNone(shutdown_resp["result"])

    def test_cli_diagnostics_command(self) -> None:
        """Verify python-hunter diagnostics CLI execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "requirements.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("requests<2.31.0\n")

            # GCC format
            import io
            from contextlib import redirect_stdout

            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = run_diagnostics_command([file_path, "--format", "gcc", "--fail-on", "none"])

            self.assertEqual(exit_code, 0)
            output_str = out.getvalue()
            self.assertIn("requirements.txt:1:1:", output_str)
            self.assertIn("[PYH-DEP-002]", output_str)

            # JSON format
            out_json = io.StringIO()
            with redirect_stdout(out_json):
                exit_code = run_diagnostics_command([file_path, "--format", "json", "--fail-on", "none"])

            self.assertEqual(exit_code, 0)
            data = json.loads(out_json.getvalue())
            self.assertIsInstance(data, list)
            self.assertGreaterEqual(len(data), 1)


if __name__ == "__main__":
    unittest.main()
