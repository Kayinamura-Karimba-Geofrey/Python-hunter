"""Standard AST Parser Implementation."""

import ast
import os
from python_hunter.domain.ast.interfaces import ASTParserEngine, ASTSourceLoader
from python_hunter.domain.ast.models import ASTDocument, ASTParseError
from python_hunter.infrastructure.ast.source_loader import SafeSourceLoader
from python_hunter.infrastructure.ast.visitor import ComprehensiveASTVisitor


class StandardASTParser(ASTParserEngine):
    """Standard library ast.parse wrapper with safe source loading and error reporting."""

    def __init__(self, loader: ASTSourceLoader | None = None) -> None:
        self.loader = loader or SafeSourceLoader()

    def parse_file(self, file_path: str, root_path: str = "") -> ASTDocument:
        """Parse source file into ASTDocument without executing untrusted code."""
        rel_path = os.path.relpath(file_path, root_path) if root_path else file_path

        try:
            content, lines = self.loader.load_source(file_path)
        except Exception as e:
            err = ASTParseError(
                file_path=rel_path,
                error_type="LOAD_ERROR",
                message=str(e),
            )
            return ASTDocument(file_path=rel_path, module_name=rel_path, parse_error=err)

        try:
            parsed_tree = ast.parse(content, filename=file_path)
            visitor = ComprehensiveASTVisitor()
            doc = visitor.visit_tree(parsed_tree, rel_path, lines)
            return doc
        except SyntaxError as se:
            err = ASTParseError(
                file_path=rel_path,
                error_type="SYNTAX_ERROR",
                message=se.msg,
                line=se.lineno,
                column=se.offset,
            )
            return ASTDocument(file_path=rel_path, module_name=rel_path, source_lines=lines, parse_error=err)
        except Exception as ex:
            err = ASTParseError(
                file_path=rel_path,
                error_type="PARSER_ERROR",
                message=str(ex),
            )
            return ASTDocument(file_path=rel_path, module_name=rel_path, source_lines=lines, parse_error=err)
