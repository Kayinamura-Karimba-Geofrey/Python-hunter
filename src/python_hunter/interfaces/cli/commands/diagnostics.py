"""CLI Command Handler for Direct In-Editor Diagnostics (python-hunter diagnostics).

Outputs editor-ready diagnostics in GCC/Unix, LSP, CodeClimate, and Reviewdog JSON formats.
"""

import argparse
import json
import os
import sys
from typing import Any

from python_hunter.interfaces.lsp.analyzer import LSPSecurityAnalyzer
from python_hunter.interfaces.lsp.protocol import path_to_uri


def run_diagnostics_command(args: list[str]) -> int:
    """Execute python-hunter diagnostics command."""
    parser = argparse.ArgumentParser(
        prog="python-hunter diagnostics",
        description="Emit security diagnostics in editor-friendly formats for VS Code, JetBrains, Vim, and CI.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or project directory to evaluate (default: .)",
    )
    parser.add_argument(
        "--format",
        choices=["gcc", "lsp", "json", "codeclimate", "rdjson"],
        default="gcc",
        help="Output format (gcc: standard compiler/editor lint lines, lsp: raw LSP diagnostics, codeclimate: GitLab/CodeClimate, rdjson: Reviewdog)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Exit with failure status if findings meet or exceed this severity (default: high)",
    )

    parsed = parser.parse_args(args)
    analyzer = LSPSecurityAnalyzer()

    # Discover files to analyze
    target_path = os.path.abspath(parsed.target)
    files_to_scan: list[str] = []

    if os.path.isfile(target_path):
        files_to_scan = [target_path]
    elif os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", ".venv", "node_modules", "dist", "build", "__pycache__")]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                name = f.lower()
                if (
                    ext in (".py", ".pyw", ".pyi", ".json", ".toml", ".yml", ".yaml", ".env")
                    or name in ("requirements.txt", "requirements-dev.txt", "package.json", "pyproject.toml")
                ):
                    files_to_scan.append(os.path.join(root, f))
    else:
        sys.stderr.write(f"Error: Target path does not exist: {parsed.target}\n")
        return 1

    all_diagnostics_by_file: dict[str, list[dict[str, Any]]] = {}
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "hint": 0, "info": 0}
    threshold = severity_order.get(parsed.fail_on, 3)
    has_violations = False

    for file_path in files_to_scan:
        uri = path_to_uri(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue

        diags = analyzer.analyze_document(uri, content)
        if diags:
            all_diagnostics_by_file[file_path] = diags
            for d in diags:
                sev_num = d.get("severity", 2)
                # LSP: 1=Error (High/Crit), 2=Warning (Med), 3=Info (Low), 4=Hint
                sev_str = "critical" if sev_num == 1 else "medium" if sev_num == 2 else "low"
                if parsed.fail_on != "none" and severity_order.get(sev_str, 0) >= threshold:
                    has_violations = True

    # Output formatting
    if parsed.format == "gcc":
        # Standard GCC format: path:line:col: severity: [code] message
        for file_path, diags in all_diagnostics_by_file.items():
            rel_path = os.path.relpath(file_path, os.getcwd()) if file_path.startswith(os.getcwd()) else file_path
            for d in diags:
                r = d.get("range", {})
                start = r.get("start", {})
                line = start.get("line", 0) + 1
                col = start.get("character", 0) + 1
                sev_code = d.get("severity", 2)
                sev_label = "error" if sev_code == 1 else "warning" if sev_code == 2 else "info"
                code = d.get("code", "PYH")
                # First line of message
                msg = d.get("message", "").splitlines()[0]
                sys.stdout.write(f"{rel_path}:{line}:{col}: {sev_label}: [{code}] {msg}\n")

    elif parsed.format == "lsp":
        sys.stdout.write(json.dumps(all_diagnostics_by_file, indent=2))
        sys.stdout.write("\n")

    elif parsed.format == "json":
        flattened = []
        for file_path, diags in all_diagnostics_by_file.items():
            for d in diags:
                flattened.append({"file": file_path, **d})
        sys.stdout.write(json.dumps(flattened, indent=2))
        sys.stdout.write("\n")

    elif parsed.format == "codeclimate":
        # CodeClimate / GitLab format
        issues = []
        for file_path, diags in all_diagnostics_by_file.items():
            rel_path = os.path.relpath(file_path, os.getcwd()) if file_path.startswith(os.getcwd()) else file_path
            for d in diags:
                r = d.get("range", {})
                start = r.get("start", {})
                line = start.get("line", 0) + 1
                sev_code = d.get("severity", 2)
                severity_str = "critical" if sev_code == 1 else "major" if sev_code == 2 else "minor"
                issues.append(
                    {
                        "description": d.get("message", "").splitlines()[0],
                        "check_name": d.get("code", "python-hunter"),
                        "fingerprint": f"{file_path}:{line}:{d.get('code')}",
                        "severity": severity_str,
                        "location": {
                            "path": rel_path,
                            "lines": {"begin": line},
                        },
                    }
                )
        sys.stdout.write(json.dumps(issues, indent=2))
        sys.stdout.write("\n")

    elif parsed.format == "rdjson":
        # Reviewdog Diagnostic JSON format
        diagnostics_list = []
        for file_path, diags in all_diagnostics_by_file.items():
            rel_path = os.path.relpath(file_path, os.getcwd()) if file_path.startswith(os.getcwd()) else file_path
            for d in diags:
                r = d.get("range", {})
                start = r.get("start", {})
                diagnostics_list.append(
                    {
                        "message": d.get("message", ""),
                        "location": {
                            "path": rel_path,
                            "range": {
                                "start": {
                                    "line": start.get("line", 0) + 1,
                                    "column": start.get("character", 0) + 1,
                                },
                            },
                        },
                        "severity": "ERROR" if d.get("severity") == 1 else "WARNING",
                        "code": {"value": d.get("code", "")},
                    }
                )
        sys.stdout.write(
            json.dumps(
                {
                    "source": {"name": "python-hunter", "url": "https://github.com/Kayinamura-Karimba-Geofrey/Python-hunter"},
                    "diagnostics": diagnostics_list,
                },
                indent=2,
            )
        )
        sys.stdout.write("\n")

    return 1 if (has_violations and parsed.fail_on != "none") else 0
