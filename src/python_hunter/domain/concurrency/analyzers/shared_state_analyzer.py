"""Shared State Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.concurrency.analyzers.base import BaseConcurrencyAnalyzer
from python_hunter.domain.concurrency.models import SharedResource, StateClassification


class SharedStateAnalyzer(BaseConcurrencyAnalyzer):
    """Analyzes global variables, class-level variables, module state, and shared caches."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        resources: list[SharedResource] = []

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                # 1. Global / Nonlocal statements
                if isinstance(node, (ast.Global, ast.Nonlocal)):
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                    for name in node.names:
                        resources.append(
                            SharedResource(
                                name=name,
                                resource_type="global",
                                state_classification=StateClassification.SHARED,
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )
                # 2. ClassDef level attributes (class Counter: value = 0)
                elif isinstance(node, ast.ClassDef):
                    for stmt in node.body:
                        if isinstance(stmt, ast.Assign):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    line = getattr(stmt, "lineno", 1)
                                    loc = Location(line_start=line, line_end=line, column_start=getattr(stmt, "col_offset", 0))
                                    resources.append(
                                        SharedResource(
                                            name=f"{node.name}.{target.id}",
                                            resource_type="class_attr",
                                            state_classification=StateClassification.SHARED,
                                            file_path=doc.file_path,
                                            location=loc,
                                        )
                                    )

        return {"resources": resources}
