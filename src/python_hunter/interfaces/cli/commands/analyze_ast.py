"""CLI Command handler for AST Analysis."""

import json
import sys
from typing import Any
from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.ast.models import ASTAnalysisSummary


def format_text_summary(summary: ASTAnalysisSummary) -> str:
    """Format ASTAnalysisSummary into clean human-readable text output."""
    lines: list[str] = []
    lines.append("\n=== Python Hunter AST Analysis ===")
    lines.append(f"Files Analyzed:  {summary.files_analyzed}")
    lines.append(f"Files Parsed:    {summary.files_parsed}")
    lines.append(f"Syntax Errors:   {summary.syntax_errors}")
    lines.append("")
    lines.append(f"Imports:         {summary.total_imports}")
    lines.append(f"Functions:       {summary.total_functions}")
    lines.append(f"Classes:         {summary.total_classes}")
    lines.append(f"Calls:           {summary.total_calls}")
    lines.append(f"Assignments:     {summary.total_assignments}")
    lines.append(f"Decorators:      {summary.total_decorators}")
    lines.append("\nAST analysis completed successfully.\n")
    return "\n".join(lines)


def format_json_summary(summary: ASTAnalysisSummary) -> str:
    """Format ASTAnalysisSummary into structured JSON output."""
    data: dict[str, Any] = {
        "files_analyzed": summary.files_analyzed,
        "files_parsed": summary.files_parsed,
        "syntax_errors": summary.syntax_errors,
        "total_imports": summary.total_imports,
        "total_functions": summary.total_functions,
        "total_classes": summary.total_classes,
        "total_calls": summary.total_calls,
        "total_assignments": summary.total_assignments,
        "total_decorators": summary.total_decorators,
        "errors": [
            {
                "file_path": e.file_path,
                "error_type": e.error_type,
                "message": e.message,
                "line": e.line,
                "column": e.column,
            }
            for e in summary.errors
        ],
    }
    return json.dumps(data, indent=2)


def run_analyze_ast_command(target_path: str, output_format: str = "text") -> int:
    """Execute analyze-ast CLI command."""
    try:
        use_case = AnalyzeASTUseCase()
        summary = use_case.execute(target_path)

        if output_format.lower() == "json":
            sys.stdout.write(format_json_summary(summary) + "\n")
        else:
            sys.stdout.write(format_text_summary(summary) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"Error during AST analysis: {e}\n")
        return 1
