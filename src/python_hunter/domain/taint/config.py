"""Taint Sources, Sinks, and Sanitizers Configuration Catalog."""

import os
from typing import Any
try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

from python_hunter.domain.taint.models import (
    SanitizationContext,
    TaintSinkCategory,
    TaintSourceCategory,
)


class TaintConfig:
    """Configurable catalog of taint sources, sinks, sanitizers, and limits."""

    def __init__(self) -> None:
        # Default Sources
        self.sources: dict[str, TaintSourceCategory] = {
            # Web Framework HTTP Inputs
            "request.args": TaintSourceCategory.HTTP_REQUEST,
            "request.form": TaintSourceCategory.HTTP_REQUEST,
            "request.json": TaintSourceCategory.HTTP_REQUEST,
            "request.data": TaintSourceCategory.HTTP_REQUEST,
            "request.cookies": TaintSourceCategory.HTTP_REQUEST,
            "request.headers": TaintSourceCategory.HTTP_REQUEST,
            "request.values": TaintSourceCategory.HTTP_REQUEST,
            "request.GET": TaintSourceCategory.HTTP_REQUEST,
            "request.POST": TaintSourceCategory.HTTP_REQUEST,
            "request.query_params": TaintSourceCategory.HTTP_REQUEST,
            # CLI Sources
            "sys.argv": TaintSourceCategory.CLI_ARGUMENT,
            "input": TaintSourceCategory.CLI_ARGUMENT,
            "argparse": TaintSourceCategory.CLI_ARGUMENT,
            "click": TaintSourceCategory.CLI_ARGUMENT,
            "typer": TaintSourceCategory.CLI_ARGUMENT,
            # Env Sources
            "os.environ": TaintSourceCategory.ENVIRONMENT_VARIABLE,
            "os.getenv": TaintSourceCategory.ENVIRONMENT_VARIABLE,
            # File Sources
            "open": TaintSourceCategory.FILE_READ,
            "read_text": TaintSourceCategory.FILE_READ,
            "read_bytes": TaintSourceCategory.FILE_READ,
            "file.read": TaintSourceCategory.FILE_READ,
            # DB Sources
            "cursor.fetchone": TaintSourceCategory.DATABASE_DATA,
            "cursor.fetchall": TaintSourceCategory.DATABASE_DATA,
        }

        # Default Sinks
        self.sinks: dict[str, TaintSinkCategory] = {
            # SQL Injection
            "cursor.execute": TaintSinkCategory.SQL_INJECTION,
            "cursor.executemany": TaintSinkCategory.SQL_INJECTION,
            "connection.execute": TaintSinkCategory.SQL_INJECTION,
            "db.execute": TaintSinkCategory.SQL_INJECTION,
            # Command Injection
            "os.system": TaintSinkCategory.COMMAND_INJECTION,
            "os.popen": TaintSinkCategory.COMMAND_INJECTION,
            "subprocess.run": TaintSinkCategory.COMMAND_INJECTION,
            "subprocess.Popen": TaintSinkCategory.COMMAND_INJECTION,
            "subprocess.call": TaintSinkCategory.COMMAND_INJECTION,
            "subprocess.check_output": TaintSinkCategory.COMMAND_INJECTION,
            # Code Execution
            "eval": TaintSinkCategory.CODE_EXECUTION,
            "exec": TaintSinkCategory.CODE_EXECUTION,
            "compile": TaintSinkCategory.CODE_EXECUTION,
            # Path Traversal
            "open": TaintSinkCategory.PATH_TRAVERSAL,
            "Path": TaintSinkCategory.PATH_TRAVERSAL,
            "os.remove": TaintSinkCategory.PATH_TRAVERSAL,
            "os.unlink": TaintSinkCategory.PATH_TRAVERSAL,
            "os.listdir": TaintSinkCategory.PATH_TRAVERSAL,
            # SSRF
            "requests.get": TaintSinkCategory.SSRF,
            "requests.post": TaintSinkCategory.SSRF,
            "requests.request": TaintSinkCategory.SSRF,
            "httpx.get": TaintSinkCategory.SSRF,
            "httpx.post": TaintSinkCategory.SSRF,
            "urllib.request.urlopen": TaintSinkCategory.SSRF,
            # Template Injection
            "jinja2.Template": TaintSinkCategory.TEMPLATE_INJECTION,
            "Template": TaintSinkCategory.TEMPLATE_INJECTION,
            "render_template_string": TaintSinkCategory.TEMPLATE_INJECTION,
        }

        # Sanitizers: Function name -> SanitizationContext
        self.sanitizers: dict[str, SanitizationContext] = {
            "shlex.quote": SanitizationContext.SHELL_SAFE,
            "html.escape": SanitizationContext.HTML_SAFE,
            "escape": SanitizationContext.HTML_SAFE,
            "markupsafe.escape": SanitizationContext.HTML_SAFE,
            "werkzeug.security.safe_str_cmp": SanitizationContext.GENERAL_SAFE,
            "int": SanitizationContext.GENERAL_SAFE,
            "float": SanitizationContext.GENERAL_SAFE,
            "bool": SanitizationContext.GENERAL_SAFE,
            "os.path.basename": SanitizationContext.PATH_SAFE,
        }

        # Analysis Limits
        self.max_call_depth: int = 20
        self.max_flow_depth: int = 100
        self.max_function_states: int = 10000

    @classmethod
    def load_from_yaml(cls, yaml_path: str) -> "TaintConfig":
        """Load taint configuration from YAML file."""
        config = cls()
        if not os.path.exists(yaml_path) or yaml is None:
            return config

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            taint_data = data.get("taint", {})
            for src in taint_data.get("sources", []):
                name = src.get("name")
                cat = src.get("category", "HTTP_REQUEST")
                if name:
                    config.sources[name] = TaintSourceCategory[cat]

            for snk in taint_data.get("sinks", []):
                name = snk.get("name")
                cat = snk.get("category", "SQL_INJECTION")
                if name:
                    config.sinks[name] = TaintSinkCategory[cat]

            for sntz in taint_data.get("sanitizers", []):
                name = sntz.get("name")
                ctx = sntz.get("context", "GENERAL_SAFE")
                if name:
                    config.sanitizers[name] = SanitizationContext[ctx]

            limits = taint_data.get("limits", {})
            config.max_call_depth = limits.get("max_call_depth", config.max_call_depth)
            config.max_flow_depth = limits.get("max_flow_depth", config.max_flow_depth)
            config.max_function_states = limits.get("max_function_states", config.max_function_states)
        except Exception:
            pass

        return config
