"""JavaScript & TypeScript AST parser and SecurityIR converter."""

import re
from dataclasses import dataclass
from python_hunter.domain.ir.models import IRCall, IRDataFlowEdge, IRFunction, IRLocation, IRSymbol, SecurityIR
from python_hunter.domain.language.models import Language


@dataclass
class JSNode:
    """Lightweight AST node representation for JavaScript / TypeScript constructs."""

    node_type: str
    name: str
    location: IRLocation
    code_snippet: str = ""


class JSParser:
    """Static parser for JavaScript and TypeScript source files using regex-semantic structural extraction."""

    FUNC_REGEX = re.compile(
        r"(?:async\s+)?function\s*([a-zA-Z0-9_$]*)\s*\(([^)]*)\)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>|([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{"
    )
    CALL_REGEX = re.compile(r"([a-zA-Z0-9_$.]+)\s*\(([^)]*)\)")
    IMPORT_REGEX = re.compile(r"(?:import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]|require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))")

    def parse_file(self, file_path: str, content: str) -> list[JSNode]:
        nodes = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            # Functions & Arrow Functions
            for match in self.FUNC_REGEX.finditer(line):
                func_name = match.group(1) or match.group(3) or match.group(5)
                if func_name and func_name not in ("if", "for", "while", "switch", "catch"):
                    nodes.append(
                        JSNode(
                            node_type="function",
                            name=func_name,
                            location=IRLocation(file_path=file_path, start_line=idx),
                            code_snippet=line.strip(),
                        )
                    )

            # Function & API Calls
            for match in self.CALL_REGEX.finditer(line):
                call_target = match.group(1)
                if call_target not in ("if", "for", "while", "switch", "catch", "function"):
                    nodes.append(
                        JSNode(
                            node_type="call",
                            name=call_target,
                            location=IRLocation(file_path=file_path, start_line=idx),
                            code_snippet=line.strip(),
                        )
                    )

        return nodes


class JSIRConverter:
    """Converts JavaScript/TypeScript AST nodes into Universal SecurityIR."""

    def __init__(self) -> None:
        self.parser = JSParser()

    def convert(self, file_path: str, content: str, language: Language) -> SecurityIR:
        ir = SecurityIR(language=language)
        nodes = self.parser.parse_file(file_path, content)

        for node in nodes:
            if node.node_type == "function":
                ir.functions.append(
                    IRFunction(
                        name=node.name,
                        qualified_name=f"{file_path}::{node.name}",
                        location=node.location,
                    )
                )
                ir.symbols.append(
                    IRSymbol(
                        name=node.name,
                        qualified_name=f"{file_path}::{node.name}",
                        symbol_type="function",
                        location=node.location,
                    )
                )
            elif node.node_type == "call":
                ir.calls.append(
                    IRCall(
                        caller="global",
                        callee=node.name,
                        location=node.location,
                    )
                )
                ir.dataflow_edges.append(
                    IRDataFlowEdge(
                        source="input",
                        target=node.name,
                        location=node.location,
                    )
                )

        return ir
