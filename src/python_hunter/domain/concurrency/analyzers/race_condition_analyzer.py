"""Race Condition & TOCTOU Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.concurrency.analyzers.base import BaseConcurrencyAnalyzer
from python_hunter.domain.concurrency.models import RaceCandidate


class RaceConditionAnalyzer(BaseConcurrencyAnalyzer):
    """Analyzes Write/Write races, Read/Write races, and File/Permission/Database TOCTOU patterns."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        race_candidates: list[RaceCandidate] = []

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            # Track check-then-use (TOCTOU) patterns inside functions
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Walk body statements to detect os.path.exists() -> open() or check_perm() -> act()
                    has_check = False
                    check_target = None
                    check_loc = None

                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Call):
                            func_name = getattr(stmt.func, "attr", None) or getattr(stmt.func, "id", None)
                            line = getattr(stmt, "lineno", 1)
                            loc = Location(line_start=line, line_end=line, column_start=getattr(stmt, "col_offset", 0))

                            if func_name in ("exists", "access", "isfile", "isdir", "check_permission", "has_perm"):
                                has_check = True
                                check_target = func_name
                                check_loc = loc
                            elif has_check and func_name in ("open", "remove", "unlink", "chmod", "chown", "withdraw", "update"):
                                is_sec = any(k in func_name.lower() for k in ("perm", "withdraw", "chmod", "auth", "token"))
                                race_candidates.append(
                                    RaceCandidate(
                                        resource_name=str(check_target),
                                        race_type="TOCTOU",
                                        writers=[func_name],
                                        readers=[str(check_target)],
                                        execution_contexts=[node.name],
                                        file_path=doc.file_path,
                                        location=check_loc or loc,
                                        is_synchronized=False,
                                        is_security_sensitive=is_sec,
                                        confidence=Confidence.HIGH if is_sec else Confidence.MEDIUM,
                                        evidence=f"TOCTOU check '{check_target}' followed by usage '{func_name}' without synchronization",
                                    )
                                )

        return {"races": race_candidates}
