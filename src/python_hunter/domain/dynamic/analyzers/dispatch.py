"""Dynamic Dispatch Analyzer Implementation."""

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


class DynamicDispatchAnalyzer(BaseDynamicAnalyzer):
    """Analyzes function maps, callback tables, getattr(obj, var)(), and globals()[var]()."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                # Detect handlers = {"cmd1": fn1, "cmd2": fn2} or dispatch map lookup handlers[user_input]()
                if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                    map_name = node.value.id
                    if any(k in map_name.lower() for k in ("handlers", "dispatch", "routes", "callbacks", "commands", "actions")):
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.DYNAMIC_DISPATCH,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.PARTIAL,
                                source=map_name,
                                evidence=f"Dynamic dispatch lookup on map: {map_name}[...]",
                                metadata={"map_name": map_name},
                            )
                        )
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
                    inner_func = getattr(node.func.func, "id", None) or getattr(node.func.func, "attr", None)
                    if inner_func in ("getattr", "globals", "locals"):
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.DYNAMIC_DISPATCH,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.UNKNOWN,
                                source=inner_func,
                                evidence=f"Dynamic dispatch execution via {inner_func}(...)()",
                            )
                        )
        return behaviors
