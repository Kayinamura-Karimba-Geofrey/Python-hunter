"""Reflection Analyzer Implementation."""

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


class ReflectionAnalyzer(BaseDynamicAnalyzer):
    """Analyzes getattr, setattr, hasattr, delattr, globals(), locals(), vars()."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name in ("getattr", "hasattr", "delattr"):
                        if len(node.args) >= 2:
                            attr_arg = node.args[1]
                            if isinstance(attr_arg, (ast.Constant, ast.Str)):
                                val = getattr(attr_arg, "value", None) or getattr(attr_arg, "s", None)
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.REFLECTION,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.HIGH,
                                        resolution_state=ResolutionState.EXACT,
                                        target=str(val),
                                        source=func_name,
                                        resolved_targets=[str(val)],
                                        evidence=f"{func_name}(..., '{val}')",
                                    )
                                )
                            else:
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.REFLECTION,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.MEDIUM,
                                        resolution_state=ResolutionState.UNKNOWN,
                                        source=func_name,
                                        unresolved_targets=["<dynamic>"],
                                        evidence=f"Dynamic {func_name} with variable attribute expression",
                                    )
                                )
                    elif func_name == "setattr":
                        if len(node.args) >= 2:
                            attr_arg = node.args[1]
                            if isinstance(attr_arg, (ast.Constant, ast.Str)):
                                val = getattr(attr_arg, "value", None) or getattr(attr_arg, "s", None)
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.REFLECTION,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.HIGH,
                                        resolution_state=ResolutionState.EXACT,
                                        target=str(val),
                                        source="setattr",
                                        resolved_targets=[str(val)],
                                        evidence=f"setattr(..., '{val}', ...)",
                                    )
                                )
                            else:
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.REFLECTION,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.MEDIUM,
                                        resolution_state=ResolutionState.UNKNOWN,
                                        source="setattr",
                                        unresolved_targets=["<dynamic>"],
                                        evidence="Dynamic setattr with variable attribute name",
                                    )
                                )
                    elif func_name in ("globals", "locals", "vars"):
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.REFLECTION,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.PARTIAL,
                                source=func_name,
                                evidence=f"Direct call to {func_name}() symbol dictionary",
                            )
                        )
        return behaviors
