"""Concrete AST Security & Intelligence Analyzer."""

import os
from typing import Any
from python_hunter.domain.analysis.base import Analyzer
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.analysis.result import AnalysisResult
from python_hunter.domain.common.enums import Category
from python_hunter.infrastructure.ast.parser import StandardASTParser


class ASTAnalyzer(Analyzer):
    """AST Security & Code Intelligence Analyzer implementing Step 1 Analyzer contract."""

    def __init__(self, parser: StandardASTParser | None = None) -> None:
        self.parser = parser or StandardASTParser()

    @property
    def name(self) -> str:
        return "ast-analyzer"

    @property
    def category(self) -> Category:
        return Category.CODE_INJECTION

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """Execute AST structural extraction across project target files."""
        documents = []
        errors = []

        root = context.project.root_path
        for tf in context.target_files:
            if not tf.is_python:
                continue
            full_p = os.path.join(root, tf.relative_path)
            doc = self.parser.parse_file(full_p, root_path=root)
            if doc.parse_error:
                errors.append(doc.parse_error.message)
            documents.append(doc)

        # Store extracted AST documents in result details metadata
        details: dict[str, Any] = {
            "documents_count": len(documents),
            "parsed_successfully": len([d for d in documents if not d.parse_error]),
            "errors_count": len(errors),
        }

        return AnalysisResult(
            analyzer_name=self.name,
            findings=[],  # Security findings rules will be added in Step 4
            duration_ms=0.0,
            errors=errors,
            metadata=details,
        )
