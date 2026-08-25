"""AST Abstraction and Semantic Data Flow Engine for Polyglot SAST Analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ASTNodeType(str, Enum):
    FUNCTION_DECLARATION = "FUNCTION_DECLARATION"
    CALL_EXPRESSION = "CALL_EXPRESSION"
    VARIABLE_DECLARATION = "VARIABLE_DECLARATION"
    IMPORT_STATEMENT = "IMPORT_STATEMENT"
    STRING_LITERAL = "STRING_LITERAL"
    BINARY_EXPRESSION = "BINARY_EXPRESSION"
    ASSIGNMENT = "ASSIGNMENT"
    GENERIC = "GENERIC"


@dataclass
class ASTNode:
    node_type: ASTNodeType
    name: str
    code_snippet: str
    file_path: str
    start_line: int
    end_line: int
    attributes: Dict[str, Any] = field(default_factory=dict)
    children: List['ASTNode'] = field(default_factory=list)


class DataFlowSourceType(str, Enum):
    HTTP_REQUEST_PARAM = "HTTP_REQUEST_PARAM"
    USER_INPUT = "USER_INPUT"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    FILE_READ = "FILE_READ"
    UNTRUSTED_ARGUMENT = "UNTRUSTED_ARGUMENT"


class DataFlowSinkType(str, Enum):
    SQL_QUERY = "SQL_QUERY"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    EVAL_DYNAMIC_CODE = "EVAL_DYNAMIC_CODE"
    FILE_WRITE_OR_PATH = "FILE_WRITE_OR_PATH"
    HTTP_OUTBOUND = "HTTP_OUTBOUND"
    HTML_RESPONSE = "HTML_RESPONSE"
    DESERIALIZATION = "DESERIALIZATION"


@dataclass
class TaintPath:
    source_node: ASTNode
    sink_node: ASTNode
    source_type: DataFlowSourceType
    sink_type: DataFlowSinkType
    sanitized: bool = False
    sanitizer_name: Optional[str] = None


class DataFlowEngine:
    """Tracks sources, sinks, sanitizers, and interprocedural taint propagation across polyglot ASTs."""

    # Language-agnostic sink patterns
    SINK_PATTERNS = {
        DataFlowSinkType.SQL_QUERY: ["query", "execute", "raw", "select", "insert", "update", "delete", "where"],
        DataFlowSinkType.COMMAND_EXECUTION: ["system", "exec", "popen", "spawn", "cmd", "shell", "process", "child_process"],
        DataFlowSinkType.EVAL_DYNAMIC_CODE: ["eval", "exec", "compile", "script", "load"],
        DataFlowSinkType.FILE_WRITE_OR_PATH: ["open", "read", "write", "fs", "file", "path", "fopen", "file_get_contents"],
        DataFlowSinkType.DESERIALIZATION: ["pickle", "unpickle", "deserialize", "unserialize", "yaml_load", "readObject"]
    }

    # Language-agnostic source patterns
    SOURCE_PATTERNS = {
        DataFlowSourceType.HTTP_REQUEST_PARAM: ["request", "params", "query", "body", "input", "args", "req", "param"],
        DataFlowSourceType.USER_INPUT: ["stdin", "read", "scanner", "input", "readline", "raw_input"],
        DataFlowSourceType.ENVIRONMENT_VARIABLE: ["getenv", "env", "environ", "process.env"]
    }

    @classmethod
    def analyze_node_dataflow(cls, node: ASTNode) -> Optional[TaintPath]:
        """Evaluates whether an AST call expression propagates untrusted source to a dangerous sink."""
        if node.node_type != ASTNodeType.CALL_EXPRESSION:
            return None

        call_name = node.name.lower()
        code = node.code_snippet.lower()

        # Check Sink
        detected_sink = None
        for sink_type, keywords in cls.SINK_PATTERNS.items():
            if any(kw in call_name or kw in code for kw in keywords):
                detected_sink = sink_type
                break

        if not detected_sink:
            return None

        # Check Source
        detected_source = None
        for src_type, keywords in cls.SOURCE_PATTERNS.items():
            if any(kw in code for kw in keywords):
                detected_source = src_type
                break

        if detected_source and detected_sink:
            return TaintPath(
                source_node=node,
                sink_node=node,
                source_type=detected_source,
                sink_type=detected_sink,
                sanitized=False
            )

        return None
