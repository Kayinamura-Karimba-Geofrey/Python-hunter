"""ParserProvider abstraction for static syntax parsing with failure isolation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import ast


@dataclass
class ParseDiagnostic:
    file_path: str
    line: int
    column: int
    message: str
    severity: str = "ERROR"  # ERROR, WARNING, INFO


@dataclass
class ParseResult:
    file_path: str
    ast: Optional[Any]
    is_partial: bool
    diagnostics: List[ParseDiagnostic] = field(default_factory=list)


class ParserProvider:
    """Provides language-specific static AST parsers with failure isolation."""

    @staticmethod
    def parse_python(code: str, file_path: str) -> ParseResult:
        diagnostics = []
        try:
            tree = ast.parse(code, filename=file_path)
            return ParseResult(file_path=file_path, ast=tree, is_partial=False, diagnostics=[])
        except SyntaxError as se:
            diagnostics.append(
                ParseDiagnostic(
                    file_path=file_path,
                    line=se.lineno or 1,
                    column=se.offset or 1,
                    message=f"Python Syntax Error: {se.msg}",
                )
            )
            # Partial recovery: try line-by-line function/class Regex extraction if AST parsing fails
            partial_ast = {"type": "PartialPythonAST", "raw_content": code}
            return ParseResult(file_path=file_path, ast=partial_ast, is_partial=True, diagnostics=diagnostics)

    @staticmethod
    def parse_generic_structural(code: str, file_path: str, language: str) -> ParseResult:
        """Generic structural AST fallback parser for C/C++/Java/Go/Rust/PHP/Ruby."""
        diagnostics = []
        lines = code.splitlines()
        nodes = []
        in_block = False
        block_name = ""

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            # Simple fault-tolerant regex/tokenizer extraction
            if trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("/*"):
                continue
            if "class " in trimmed or "struct " in trimmed or "interface " in trimmed or "trait " in trimmed or "package " in trimmed or "namespace " in trimmed:
                nodes.append({"type": "StructureDeclaration", "line": idx, "code": trimmed})
            elif "func " in trimmed or "def " in trimmed or "public " in trimmed or "private " in trimmed or "fn " in trimmed or "function " in trimmed or "void " in trimmed or "int " in trimmed:
                nodes.append({"type": "FunctionDeclaration", "line": idx, "code": trimmed})
            elif "import " in trimmed or "use " in trimmed or "#include" in trimmed or "require" in trimmed or "include_once" in trimmed:
                nodes.append({"type": "ImportDeclaration", "line": idx, "code": trimmed})

        generic_ast = {
            "type": f"Generic{language.capitalize()}AST",
            "file_path": file_path,
            "declarations": nodes,
            "total_lines": len(lines),
        }
        return ParseResult(file_path=file_path, ast=generic_ast, is_partial=False, diagnostics=diagnostics)
