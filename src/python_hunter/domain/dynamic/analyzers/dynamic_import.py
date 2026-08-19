"""Dynamic Import Analyzer Implementation."""

import ast
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dynamic.analyzers.base import BaseDynamicAnalyzer
from python_hunter.domain.dynamic.analyzers.dynamic_resolver import DynamicResolver
from python_hunter.domain.dynamic.models import (

    DynamicBehavior,
    DynamicBehaviorType,
    ResolutionState,
)


class DynamicImportAnalyzer(BaseDynamicAnalyzer):
    """Analyzes __import__, importlib.import_module, and import_module with constant resolution and allowlists."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        resolver = DynamicResolver()

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            env = resolver.build_local_env(tree)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name in ("__import__", "import_module"):
                        if node.args:
                            mod_arg = node.args[0]
                            possible_mods = resolver.resolve_expression(mod_arg, env)

                            if possible_mods and all(isinstance(m, str) for m in possible_mods):
                                mod_list = list(possible_mods)
                                state = ResolutionState.EXACT if len(mod_list) == 1 else ResolutionState.PARTIAL
                                behaviors.append(
                                    DynamicBehavior(
                                        behavior_type=DynamicBehaviorType.DYNAMIC_IMPORT,
                                        file_path=doc.file_path,
                                        location=loc,
                                        confidence=Confidence.HIGH,
                                        resolution_state=state,
                                        target=mod_list[0] if len(mod_list) == 1 else None,
                                        source=func_name,
                                        resolved_targets=mod_list,
                                        evidence=f"{func_name}(...) resolved to targets: {mod_list}",
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
                                        evidence=f"Dynamic module import using variable expression: {func_name}(...)",
                                    )
                                )
        return behaviors

