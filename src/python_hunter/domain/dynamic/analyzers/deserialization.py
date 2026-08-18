"""Deserialization Analyzer Implementation."""

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


class DeserializationAnalyzer(BaseDynamicAnalyzer):
    """Analyzes pickle, yaml, marshal, and custom __reduce__ methods."""

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
                    mod_name = None
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        mod_name = node.func.value.id

                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if mod_name == "pickle" and func_name in ("loads", "load", "Unpickler"):
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.DESERIALIZATION,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.HIGH_CONFIDENCE,
                                source=f"pickle.{func_name}",
                                evidence=f"Unsafe pickle deserialization call: pickle.{func_name}()",
                                metadata={"deserializer": "pickle"},
                            )
                        )
                    elif mod_name == "yaml" and func_name in ("load", "unsafe_load", "full_load"):
                        is_safe = False
                        if func_name == "load":
                            for kw in node.keywords:
                                if kw.arg == "Loader":
                                    loader_name = getattr(kw.value, "id", None) or getattr(kw.value, "attr", None)
                                    if loader_name in ("SafeLoader", "CSafeLoader"):
                                        is_safe = True
                        if not is_safe:
                            behaviors.append(
                                DynamicBehavior(
                                    behavior_type=DynamicBehaviorType.DESERIALIZATION,
                                    file_path=doc.file_path,
                                    location=loc,
                                    confidence=Confidence.HIGH,
                                    resolution_state=ResolutionState.HIGH_CONFIDENCE,
                                    source=f"yaml.{func_name}",
                                    evidence=f"Potentially unsafe YAML loading: yaml.{func_name}()",
                                    metadata={"deserializer": "yaml", "is_safe": is_safe},
                                )
                            )
                    elif mod_name == "marshal" and func_name in ("loads", "load"):
                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.DESERIALIZATION,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH,
                                resolution_state=ResolutionState.HIGH_CONFIDENCE,
                                source=f"marshal.{func_name}",
                                evidence=f"Marshal deserialization call: marshal.{func_name}()",
                                metadata={"deserializer": "marshal"},
                            )
                        )
                elif isinstance(node, ast.FunctionDef) and node.name == "__reduce__":
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                    behaviors.append(
                        DynamicBehavior(
                            behavior_type=DynamicBehaviorType.DESERIALIZATION,
                            file_path=doc.file_path,
                            location=loc,
                            confidence=Confidence.HIGH,
                            resolution_state=ResolutionState.EXACT,
                            source="__reduce__",
                            evidence=f"Custom pickle serialization hook defined: {node.name}()",
                            metadata={"hook": "__reduce__"},
                        )
                    )
        return behaviors
