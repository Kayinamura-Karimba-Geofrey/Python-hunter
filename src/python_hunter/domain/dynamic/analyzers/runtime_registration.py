"""Runtime Registration Analyzer Implementation."""

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


class RuntimeRegistrationAnalyzer(BaseDynamicAnalyzer):
    """Analyzes runtime registrations like registry.register(), signal.connect(), app.add_url_rule()."""

    def analyze(self, documents: list[ASTDocument]) -> list[DynamicBehavior]:
        behaviors = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name in ("register", "connect", "add_url_rule", "add_api_route", "register_blueprint"):
                        target = None
                        if node.args:
                            first_arg = node.args[0]
                            if isinstance(first_arg, (ast.Constant, ast.Str)):
                                target = str(getattr(first_arg, "value", None) or getattr(first_arg, "s", None))
                            elif isinstance(first_arg, ast.Name):
                                target = first_arg.id

                        behaviors.append(
                            DynamicBehavior(
                                behavior_type=DynamicBehaviorType.RUNTIME_REGISTRATION,
                                file_path=doc.file_path,
                                location=loc,
                                confidence=Confidence.HIGH if target else Confidence.MEDIUM,
                                resolution_state=ResolutionState.EXACT if target else ResolutionState.PARTIAL,
                                target=target or "<dynamic_registration>",
                                source=func_name,
                                resolved_targets=[target] if target else [],
                                evidence=f"Runtime registration via {func_name}()",
                                metadata={"registration_method": func_name},
                            )
                        )
        return behaviors
