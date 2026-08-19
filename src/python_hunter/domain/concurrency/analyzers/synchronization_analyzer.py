"""Synchronization and Lock Order Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.concurrency.analyzers.base import BaseConcurrencyAnalyzer
from python_hunter.domain.concurrency.models import ExecutionModel, LockOrderGraph, SynchronizationObject


class SynchronizationAnalyzer(BaseConcurrencyAnalyzer):
    """Analyzes Locks, Semaphores, Events, Conditions, Queues, and builds LockOrderGraph."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, Any]:
        sync_objects: list[SynchronizationObject] = []
        lock_graph = LockOrderGraph()

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                # 1. Lock / Semaphore / Event / Queue creations
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name in ("Lock", "RLock", "Semaphore", "Event", "Condition", "Queue"):
                        sync_objects.append(
                            SynchronizationObject(
                                name=f"{func_name}_{line}",
                                sync_type=func_name,
                                execution_model=ExecutionModel.THREAD if "threading" in str(getattr(node.func, "value", "")) else ExecutionModel.ASYNC_TASK,
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )

                # 2. Nested context managers (with lock1: with lock2:) for lock graph ordering
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        ctx_expr = item.context_expr
                        lock_name = getattr(ctx_expr, "id", None) or getattr(ctx_expr, "attr", None)
                        if lock_name:
                            # Check nested with blocks
                            for child in ast.walk(node):
                                if child is not node and isinstance(child, (ast.With, ast.AsyncWith)):
                                    for sub_item in child.items:
                                        sub_lock = getattr(sub_item.context_expr, "id", None) or getattr(sub_item.context_expr, "attr", None)
                                        if sub_lock and sub_lock != lock_name:
                                            line = getattr(child, "lineno", 1)
                                            loc = Location(line_start=line, line_end=line, column_start=getattr(child, "col_offset", 0))
                                            lock_graph.add_edge(lock_name, sub_lock, doc.file_path, loc)

        return {
            "sync_objects": sync_objects,
            "lock_graph": lock_graph,
        }
