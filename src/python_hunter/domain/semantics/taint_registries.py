"""Centralized Taint Source, Sink, and Context-Aware Sanitizer Registries."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class SourceCategory(str, Enum):
    HTTP_INPUT = "http_input"
    QUERY_PARAM = "query_param"
    REQUEST_BODY = "request_body"
    HEADER = "header"
    COOKIE = "cookie"
    ENV_VAR = "env_var"
    FILE = "file"
    DATABASE = "database"
    EXTERNAL_API = "external_api"
    MESSAGE_QUEUE = "message_queue"


class SinkCategory(str, Enum):
    SQL = "sql"
    SHELL_EXEC = "shell_exec"
    FILESYSTEM = "filesystem"
    HTTP_REQUEST = "http_request"
    TEMPLATE_RENDERING = "template_rendering"
    HTML_OUTPUT = "html_output"
    DESERIALIZATION = "deserialization"
    REDIRECT = "redirect"
    LOGGING = "logging"
    CRYPTOGRAPHY = "cryptography"


@dataclass
class TaintSourceDef:
    name: str
    category: SourceCategory
    pattern: str  # Function, attribute, or parameter pattern
    description: str


@dataclass
class TaintSinkDef:
    name: str
    category: SinkCategory
    pattern: str  # Function or API pattern
    vulnerability_type: str
    cwe: str
    owasp: str


@dataclass
class SanitizerDef:
    name: str
    pattern: str  # Function or transformation pattern
    effective_categories: Set[SinkCategory]  # Vulnerability classes it actually mitigates
    description: str


class SanitizerContext:
    """Validates whether a sanitizer is effective for a given target sink category."""

    @staticmethod
    def is_sanitizer_effective(sanitizer: SanitizerDef, target_sink_category: SinkCategory) -> bool:
        """Returns True ONLY if the sanitizer is registered as effective for target sink category."""
        return target_sink_category in sanitizer.effective_categories


class TaintSourceRegistry:
    """Centralized registry for untrusted data sources across all languages."""

    def __init__(self) -> None:
        self.sources: Dict[str, TaintSourceDef] = {}
        self._bootstrap_sources()

    def _bootstrap_sources(self) -> None:
        defaults = [
            # HTTP / Query / Body / Headers / Cookies
            TaintSourceDef("http_request_args", SourceCategory.QUERY_PARAM, "request.args", "HTTP GET query parameters"),
            TaintSourceDef("http_request_form", SourceCategory.REQUEST_BODY, "request.form", "HTTP POST form data"),
            TaintSourceDef("http_request_json", SourceCategory.REQUEST_BODY, "request.json", "HTTP JSON body payload"),
            TaintSourceDef("http_request_headers", SourceCategory.HEADER, "request.headers", "HTTP request headers"),
            TaintSourceDef("http_request_cookies", SourceCategory.COOKIE, "request.cookies", "HTTP cookies"),
            TaintSourceDef("servlet_param", SourceCategory.QUERY_PARAM, "request.getParameter", "Java Servlet query parameter"),
            TaintSourceDef("gin_param", SourceCategory.QUERY_PARAM, "c.Query", "Go Gin framework query parameter"),
            TaintSourceDef("php_get", SourceCategory.QUERY_PARAM, "$_GET", "PHP GET array"),
            TaintSourceDef("php_post", SourceCategory.REQUEST_BODY, "$_POST", "PHP POST array"),
            TaintSourceDef("ruby_params", SourceCategory.QUERY_PARAM, "params", "Ruby Rails/Sinatra params hash"),
            # Environment / System / Files / Queues
            TaintSourceDef("env_var", SourceCategory.ENV_VAR, "os.environ", "System environment variables"),
            TaintSourceDef("file_read", SourceCategory.FILE, "open.read", "Untrusted file content read"),
            TaintSourceDef("mq_consume", SourceCategory.MESSAGE_QUEUE, "mq.consume", "Message queue message payload"),
        ]
        for src in defaults:
            self.sources[src.name] = src

    def register_source(self, source: TaintSourceDef) -> None:
        self.sources[source.name] = source

    def matches(self, code_snippet: str) -> List[TaintSourceDef]:
        matched = []
        for src in self.sources.values():
            if src.pattern in code_snippet:
                matched.append(src)
        return matched


class TaintSinkRegistry:
    """Centralized registry for dangerous security sinks across all languages."""

    def __init__(self) -> None:
        self.sinks: Dict[str, TaintSinkDef] = {}
        self._bootstrap_sinks()

    def _bootstrap_sinks(self) -> None:
        defaults = [
            # SQL
            TaintSinkDef("sql_execute", SinkCategory.SQL, "cursor.execute", "SQL Injection", "CWE-89", "A03:2021-Injection"),
            TaintSinkDef("java_sql_stmt", SinkCategory.SQL, "stmt.executeQuery", "SQL Injection", "CWE-89", "A03:2021-Injection"),
            TaintSinkDef("go_db_query", SinkCategory.SQL, "db.Query", "SQL Injection", "CWE-89", "A03:2021-Injection"),
            # Shell Exec
            TaintSinkDef("os_system", SinkCategory.SHELL_EXEC, "os.system", "Command Injection", "CWE-78", "A03:2021-Injection"),
            TaintSinkDef("subprocess_exec", SinkCategory.SHELL_EXEC, "subprocess.call", "Command Injection", "CWE-78", "A03:2021-Injection"),
            TaintSinkDef("runtime_exec", SinkCategory.SHELL_EXEC, "Runtime.getRuntime().exec", "Command Injection", "CWE-78", "A03:2021-Injection"),
            TaintSinkDef("go_exec", SinkCategory.SHELL_EXEC, "exec.Command", "Command Injection", "CWE-78", "A03:2021-Injection"),
            # Filesystem / Path Traversal
            TaintSinkDef("file_open", SinkCategory.FILESYSTEM, "open(", "Path Traversal", "CWE-22", "A01:2021-Broken Access Control"),
            TaintSinkDef("java_file_open", SinkCategory.FILESYSTEM, "new File(", "Path Traversal", "CWE-22", "A01:2021-Broken Access Control"),
            # SSRF
            TaintSinkDef("http_get_ssrf", SinkCategory.HTTP_REQUEST, "requests.get", "Server-Side Request Forgery", "CWE-918", "A10:2021-SSRF"),
            TaintSinkDef("go_http_get", SinkCategory.HTTP_REQUEST, "http.Get", "Server-Side Request Forgery", "CWE-918", "A10:2021-SSRF"),
            # Deserialization
            TaintSinkDef("pickle_loads", SinkCategory.DESERIALIZATION, "pickle.loads", "Insecure Deserialization", "CWE-502", "A08:2021-Integrity Failures"),
            TaintSinkDef("java_readobject", SinkCategory.DESERIALIZATION, "in.readObject", "Insecure Deserialization", "CWE-502", "A08:2021-Integrity Failures"),
            # XSS / Template
            TaintSinkDef("raw_html_render", SinkCategory.HTML_OUTPUT, "response.write", "Cross-Site Scripting", "CWE-79", "A03:2021-Injection"),
        ]
        for snk in defaults:
            self.sinks[snk.name] = snk

    def register_sink(self, sink: TaintSinkDef) -> None:
        self.sinks[sink.name] = sink

    def matches(self, code_snippet: str) -> List[TaintSinkDef]:
        matched = []
        for snk in self.sinks.values():
            if snk.pattern in code_snippet:
                matched.append(snk)
        return matched


class SanitizerRegistry:
    """Centralized registry for context-specific sanitizers."""

    def __init__(self) -> None:
        self.sanitizers: Dict[str, SanitizerDef] = {}
        self._bootstrap_sanitizers()

    def _bootstrap_sanitizers(self) -> None:
        defaults = [
            SanitizerDef("html_escape", "html.escape", {SinkCategory.HTML_OUTPUT, SinkCategory.TEMPLATE_RENDERING}, "Escapes HTML special characters"),
            SanitizerDef("shlex_quote", "shlex.quote", {SinkCategory.SHELL_EXEC}, "Quotes shell command arguments"),
            SanitizerDef("path_clean", "filepath.Clean", {SinkCategory.FILESYSTEM}, "Normalizes and cleans file path"),
            SanitizerDef("url_validate", "url.validate", {SinkCategory.HTTP_REQUEST, SinkCategory.REDIRECT}, "Validates outbound URL destination"),
            SanitizerDef("sql_parameterized", "prepare_statement", {SinkCategory.SQL}, "Uses parameterized SQL query placeholder"),
            SanitizerDef("int_cast", "int", {SinkCategory.SQL, SinkCategory.FILESYSTEM, SinkCategory.SHELL_EXEC}, "Converts untrusted input into bounded integer value"),
        ]
        for san in defaults:
            self.sanitizers[san.name] = san

    def register_sanitizer(self, sanitizer: SanitizerDef) -> None:
        self.sanitizers[sanitizer.name] = sanitizer

    def matches(self, code_snippet: str) -> List[SanitizerDef]:
        matched = []
        for san in self.sanitizers.values():
            if san.pattern in code_snippet:
                matched.append(san)
        return matched
