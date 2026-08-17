"""Comprehensive AST Node Visitor."""

import ast
from python_hunter.domain.ast.interfaces import ASTVisitorInterface
from python_hunter.domain.ast.models import (
    AssignmentInfo,
    ASTDocument,
    ASTLocation,
    CallInfo,
    ClassInfo,
    DecoratorInfo,
    FunctionInfo,
    ImportInfo,
)


class ComprehensiveASTVisitor(ast.NodeVisitor, ASTVisitorInterface):
    """Traverses Python AST nodes extracting structural metadata and tracking import aliases."""

    def __init__(self) -> None:
        self.file_path: str = ""
        self.source_lines: list[str] = []
        self.alias_map: dict[str, str] = {}
        
        self.imports: list[ImportInfo] = []
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.calls: list[CallInfo] = []
        self.assignments: list[AssignmentInfo] = []
        self.decorators: list[DecoratorInfo] = []
        self.constants: list[str] = []

    def visit_tree(self, tree: ast.AST, file_path: str, source_lines: list[str]) -> ASTDocument:
        """Traverse AST tree and return ASTDocument."""
        self.file_path = file_path
        self.source_lines = source_lines
        self.alias_map.clear()
        self.imports.clear()
        self.functions.clear()
        self.classes.clear()
        self.calls.clear()
        self.assignments.clear()
        self.decorators.clear()
        self.constants.clear()

        self.visit(tree)

        mod_name = file_path.replace("/", ".").rstrip(".py")
        return ASTDocument(
            file_path=file_path,
            module_name=mod_name,
            source_lines=source_lines,
            imports=self.imports,
            functions=self.functions,
            classes=self.classes,
            calls=self.calls,
            assignments=self.assignments,
            decorators=self.decorators,
            constants=self.constants,
        )

    def _get_location(self, node: ast.AST) -> ASTLocation | None:
        """Extract location metadata from AST node."""
        if hasattr(node, "lineno") and hasattr(node, "col_offset"):
            return ASTLocation(
                file_path=self.file_path,
                line_start=node.lineno,
                column_start=node.col_offset,
                line_end=getattr(node, "end_lineno", node.lineno),
                column_end=getattr(node, "end_col_offset", node.col_offset),
            )
        return None

    def visit_Import(self, node: ast.Import) -> None:
        """Process 'import x' and 'import x as y'."""
        loc = self._get_location(node)
        for alias in node.names:
            mod_name = alias.name
            as_name = alias.asname
            if as_name:
                self.alias_map[as_name] = mod_name

            self.imports.append(
                ImportInfo(
                    module=mod_name,
                    imported_name=None,
                    alias=as_name,
                    is_from_import=False,
                    location=loc,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Process 'from x import y' and 'from x import y as z'."""
        loc = self._get_location(node)
        mod_name = node.module or ""
        for alias in node.names:
            item_name = alias.name
            as_name = alias.asname
            full_qualified = f"{mod_name}.{item_name}" if mod_name else item_name
            if as_name:
                self.alias_map[as_name] = full_qualified
            else:
                self.alias_map[item_name] = full_qualified

            self.imports.append(
                ImportInfo(
                    module=mod_name,
                    imported_name=item_name,
                    alias=as_name,
                    is_from_import=True,
                    location=loc,
                )
            )
        self.generic_visit(node)

    def _resolve_name(self, node: ast.AST) -> str:
        """Extract name string from AST node (Name, Attribute, etc.)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        return "<dynamic>"

    def _extract_decorators(self, decorator_list: list[ast.expr]) -> list[DecoratorInfo]:
        """Extract decorator information."""
        decs: list[DecoratorInfo] = []
        for dec in decorator_list:
            dec_name = self._resolve_name(dec)
            arg_count = len(dec.args) if isinstance(dec, ast.Call) else 0
            decs.append(
                DecoratorInfo(
                    name=dec_name,
                    arguments_count=arg_count,
                    location=self._get_location(dec),
                )
            )
            self.decorators.append(decs[-1])
        return decs

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Process synchronous function definitions."""
        self._handle_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Process asynchronous function definitions."""
        self._handle_function(node, is_async=True)

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        loc = self._get_location(node)
        args = [a.arg for a in node.args.args]
        decs = self._extract_decorators(node.decorator_list)

        fn_info = FunctionInfo(
            name=node.name,
            qualified_name=node.name,
            is_async=is_async,
            arguments=args,
            decorators=decs,
            location=loc,
        )
        self.functions.append(fn_info)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Process class definitions."""
        loc = self._get_location(node)
        bases = [self._resolve_name(b) for b in node.bases]
        decs = self._extract_decorators(node.decorator_list)

        cls_info = ClassInfo(
            name=node.name,
            bases=bases,
            methods=[],
            decorators=decs,
            location=loc,
        )
        self.classes.append(cls_info)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Process function calls and resolve aliases."""
        loc = self._get_location(node)
        raw_name = self._resolve_name(node.func)

        # Alias resolution
        resolved = None
        first_part = raw_name.split(".")[0]
        if first_part in self.alias_map:
            target = self.alias_map[first_part]
            resolved = raw_name.replace(first_part, target, 1)

        qual_name = resolved or raw_name
        kw_args: dict[str, str] = {}
        for kw in node.keywords:
            if kw.arg:
                if isinstance(kw.value, ast.Constant):
                    kw_args[kw.arg] = str(kw.value.value)
                elif isinstance(kw.value, ast.Name):
                    kw_args[kw.arg] = kw.value.id
                else:
                    kw_args[kw.arg] = "<expression>"

        self.calls.append(
            CallInfo(
                name=raw_name,
                qualified_name=qual_name,
                resolved_alias=resolved,
                arguments_count=len(node.args),
                keyword_arguments=kw_args,
                location=loc,
            )
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Process variable assignments."""
        loc = self._get_location(node)
        for target in node.targets:
            tgt_name = self._resolve_name(target)
            val_type = type(node.value).__name__
            self.assignments.append(
                AssignmentInfo(target=tgt_name, value_type=val_type, location=loc)
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Process constant literals."""
        if isinstance(node.value, str):
            self.constants.append(node.value)
        self.generic_visit(node)
