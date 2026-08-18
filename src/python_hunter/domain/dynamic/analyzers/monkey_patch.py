"""Monkey Patching Analyzer Implementation."""

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


class MonkeyPatchAnalyzer(BaseDynamicAnalyzer):
    """Analyzes runtime attribute re-assignments (Class.method = replacement, module.fn = replacement)."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                            obj_name = target.value.id
                            attr_name = target.attr
                            line = getattr(node, "lineno", 1)
                            loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                            # Heuristic: module or class attribute re-assignment at runtime
                            val_name = getattr(node.value, "id", None) or getattr(node.value, "name", None) or "<expression>"
                            behaviors.append(
                                DynamicBehavior(
                                    behavior_type=DynamicBehaviorType.MONKEY_PATCH,
                                    file_path=doc.file_path,
                                    location=loc,
                                    confidence=Confidence.MEDIUM,
                                    resolution_state=ResolutionState.HIGH_CONFIDENCE,
                                    target=f"{obj_name}.{attr_name}",
                                    source=str(val_name),
                                    evidence=f"Monkey patch: {obj_name}.{attr_name} = {val_name}",
                                    metadata={"target_object": obj_name, "attribute": attr_name},
                                )
                            )
        return behaviors
