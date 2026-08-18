"""Decorator Analyzer Implementation."""

import ast
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dynamic.analyzers.base import BaseDynamicAnalyzer
from python_hunter.domain.dynamic.models import (
    DynamicBehavior,
    DynamicBehaviorType,
    ResolutionState,
)


class DecoratorAnalyzer(BaseDynamicAnalyzer):
    """Analyzes decorator chains, decorator order, and decorator factories."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    if node.decorator_list:
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        dec_names = []
                        for dec in node.decorator_list:
                            if isinstance(dec, ast.Name):
                                dec_names.append(dec.id)
                            elif isinstance(dec, ast.Call):
                                fname = getattr(dec.func, "id", None) or getattr(dec.func, "attr", None) or "factory"
                                dec_names.append(f"{fname}(...)")
                            elif isinstance(dec, ast.Attribute):
                                dec_names.append(f"{dec.value.id if isinstance(dec.value, ast.Name) else 'obj'}.{dec.attr}")

                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.DECORATOR,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.EXACT,
                                target=node.name,
                                source=", ".join(dec_names),
                                resolved_targets=dec_names,
                                evidence=f"Decorated {node.name} with [{', '.join(dec_names)}]",
                                metadata={"decorator_count": len(dec_names), "decorators": dec_names},
                            )
                        )
        return behaviors
