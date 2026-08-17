"""Analyze AST Application Use Case."""

import os
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.domain.ast.models import ASTAnalysisSummary, ASTDocument
from python_hunter.infrastructure.ast.parser import StandardASTParser


class AnalyzeASTUseCase:
    """Orchestrates Project Discovery + AST Parsing & Traversal."""

    def __init__(
        self,
        discovery_use_case: DiscoverProjectUseCase | None = None,
        parser: StandardASTParser | None = None,
    ) -> None:
        self.discovery = discovery_use_case or DiscoverProjectUseCase()
        self.parser = parser or StandardASTParser()

    def execute(self, target_path: str) -> ASTAnalysisSummary:
        """Execute AST structural analysis on target project or Python file."""
        manifest = self.discovery.discover(target_path)
        root = manifest.root_path

        summary = ASTAnalysisSummary()
        py_files = [f for f in manifest.files if f.is_python]

        summary.files_analyzed = len(py_files)

        for meta in py_files:
            full_path = os.path.join(root, meta.relative_path)
            doc: ASTDocument = self.parser.parse_file(full_path, root_path=root)

            summary.documents.append(doc)
            if doc.parse_error:
                summary.syntax_errors += 1
                summary.errors.append(doc.parse_error)
            else:
                summary.files_parsed += 1
                summary.total_imports += len(doc.imports)
                summary.total_functions += len(doc.functions)
                summary.total_classes += len(doc.classes)
                summary.total_calls += len(doc.calls)
                summary.total_assignments += len(doc.assignments)
                summary.total_decorators += len(doc.decorators)

        return summary
