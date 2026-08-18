"""Plugin Loader & Entry Points Analyzer Implementation."""

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


class PluginLoaderAnalyzer(BaseDynamicAnalyzer):
    """Analyzes importlib.metadata.entry_points(), pkg_resources entry points, and dynamic plugin loading."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name in ("entry_points", "iter_entry_points", "load_entry_point"):
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.PLUGIN_LOADING,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.PARTIAL,
                                source=func_name,
                                evidence=f"Dynamic plugin entry point discovery call: {func_name}()",
                                metadata={"entry_point_api": func_name},
                            )
                        )
        return behaviors
