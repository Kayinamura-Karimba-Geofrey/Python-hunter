"""Eval and Exec Analyzer Implementation."""

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


class EvalExecAnalyzer(BaseDynamicAnalyzer):
    """Analyzes eval(), exec(), compile() and distinguishes ast.literal_eval()."""

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

                    if func_name in ("eval", "exec", "compile"):
                        # Ensure it's not ast.literal_eval
                        if isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "ast":
                            if func_name == "literal_eval":
                                continue

                        if node.args:
                            expr_arg = node.args[0]
                            is_const = isinstance(expr_arg, (ast.Constant, ast.Str))
                            val = str(getattr(expr_arg, "value", None) or getattr(expr_arg, "s", "")) if is_const else None

                            behaviors.append(
                                DynamicBehavior(
                                    behavior_type=DynamicBehaviorType.DYNAMIC_EXECUTION,
                                    file_path=doc.file_path,
                                    location=loc,
                                    confidence=Confidence.HIGH,
                                    resolution_state=ResolutionState.EXACT if is_const else ResolutionState.UNKNOWN,
                                    target=val if is_const else "<dynamic_code>",
                                    source=func_name,
                                    evidence=f"{func_name} call with {'constant' if is_const else 'dynamic'} expression",
                                    metadata={"is_constant": is_const, "expression": val},
                                )
                            )
        return behaviors
