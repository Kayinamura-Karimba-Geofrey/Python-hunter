"""Language Server Protocol (LSP 3.17) Wire Format & Data Structures.

Implements JSON-RPC 2.0 framing, URI conversion, and standard LSP types.
"""

from enum import IntEnum
import json
import logging
import os
from pathlib import Path
from typing import Any, BinaryIO
import urllib.parse

logger = logging.getLogger(__name__)


class DiagnosticSeverity(IntEnum):
    """LSP 3.17 DiagnosticSeverity values."""

    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


class MessageType(IntEnum):
    """LSP 3.17 MessageType values."""

    ERROR = 1
    WARNING = 2
    INFO = 3
    LOG = 4


class TextDocumentSyncKind(IntEnum):
    """LSP 3.17 TextDocumentSyncKind values."""

    NONE = 0
    FULL = 1
    INCREMENTAL = 2


class CodeActionKind:
    """LSP 3.17 CodeActionKind values."""

    QUICK_FIX = "quickfix"
    REFACTOR = "refactor"
    SOURCE = "source"
    SOURCE_ORGANIZE_IMPORTS = "source.organizeImports"
    SOURCE_FIX_ALL = "source.fixAll"


def uri_to_path(uri: str) -> str:
    """Convert an LSP document URI to a local file system path."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme == "file":
        path = urllib.parse.unquote(parsed.path)
        # On Windows, /C:/path needs to be stripped of leading slash
        if os.name == "nt" and len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return os.path.abspath(path)
    return uri


def path_to_uri(path: str) -> str:
    """Convert a local file system path to an LSP document URI."""
    try:
        return Path(path).resolve().as_uri()
    except Exception:
        abs_path = os.path.abspath(path)
        return f"file://{abs_path}"


def read_lsp_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Reads a single JSON-RPC 2.0 message framed with Content-Length headers."""
    content_length: int | None = None

    while True:
        line_bytes = stream.readline()
        if not line_bytes:
            return None  # EOF

        line = line_bytes.decode("utf-8", errors="replace").strip()
        if not line:
            # Blank line marks end of headers
            if content_length is not None:
                break
            continue

        if ":" in line:
            header_name, header_val = line.split(":", 1)
            if header_name.strip().lower() == "content-length":
                try:
                    content_length = int(header_val.strip())
                except ValueError:
                    content_length = None

    if content_length is None or content_length < 0:
        return None

    body_bytes = bytearray()
    remaining = content_length
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        body_bytes.extend(chunk)
        remaining -= len(chunk)

    if len(body_bytes) < content_length:
        return None

    try:
        return json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        logger.warning(f"Failed to parse JSON-RPC message: {e}")
        return None


def write_lsp_message(stream: BinaryIO, payload: dict[str, Any]) -> None:
    """Serializes and sends a JSON-RPC 2.0 message with Content-Length framing."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    try:
        stream.write(header + body)
        stream.flush()
    except (BrokenPipeError, ConnectionResetError, IOError):
        pass


def make_response(req_id: Any, result: Any) -> dict[str, Any]:
    """Create a standard JSON-RPC 2.0 success response."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def make_error_response(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Create a standard JSON-RPC 2.0 error response."""
    resp: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if data is not None:
        resp["error"]["data"] = data
    return resp


def make_notification(method: str, params: Any) -> dict[str, Any]:
    """Create a standard JSON-RPC 2.0 notification."""
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
