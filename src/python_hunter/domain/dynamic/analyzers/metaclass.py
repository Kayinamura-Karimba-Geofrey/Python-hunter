"""Metaclass & Dynamic Class Creation Analyzer Implementation."""

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


class MetaclassAnalyzer(BaseDynamicAnalyzer):
    """Analyzes custom metaclasses, type(name, bases, dict), and types.new_class."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    meta_name = None
                    for kw in node.keywords:
                        if kw.arg == "metaclass":
                            meta_name = getattr(kw.value, "id", None) or getattr(kw.value, "attr", None)
                    if meta_name:
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.METACLASS,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.EXACT,
                                target=node.name,
                                source=str(meta_name),
                                resolved_targets=[str(meta_name)],
                                evidence=f"Class '{node.name}' uses metaclass '{meta_name}'",
                            )
                        )
                elif isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                    if func_name == "type" and len(node.args) == 3:
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        class_name = None
                        if isinstance(node.args[0], (ast.Constant, ast.Str)):
                            class_name = str(getattr(node.args[0], "value", None) or getattr(node.args[0], "s", None))

                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.METACLASS,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.EXACT if class_name else ResolutionState.UNKNOWN,
                                target=class_name if class_name else "<dynamic_class>",
                                source="type",
                                evidence=f"Dynamic class creation using type('{class_name or '...'}', ...)",
                            )
                        )
        return behaviors
