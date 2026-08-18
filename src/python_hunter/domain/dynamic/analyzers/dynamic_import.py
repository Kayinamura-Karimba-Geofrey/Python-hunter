"""Dynamic Import Analyzer Implementation."""

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


class DynamicImportAnalyzer(BaseDynamicAnalyzer):
    """Analyzes __import__, importlib.import_module, and import_module."""

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

                    if func_name in ("__import__", "import_module"):
                        if node.args:
                            mod_arg = node.args[0]
                            if isinstance(mod_arg, (ast.Constant, ast.Str)):
                                mod_name = str(getattr(mod_arg, "value", None) or getattr(mod_arg, "s", None))
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.DYNAMIC_IMPORT,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.HIGH,
                                        resolution_state=ResolutionState.HIGH_CONFIDENCE,
                                        target=mod_name,
                                        source=func_name,
                                        resolved_targets=[mod_name],
                                        evidence=f"{func_name}('{mod_name}')",
                                    )
                                )
                            else:
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.DYNAMIC_IMPORT,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.MEDIUM,
                                        resolution_state=ResolutionState.UNKNOWN,
                                        source=func_name,
                                        unresolved_targets=["<dynamic_module>"],
                                        evidence=f"Dynamic module import using variable: {func_name}(...)",
                                    )
                                )
        return behaviors
