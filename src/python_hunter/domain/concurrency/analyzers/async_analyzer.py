"""Async and Task Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.concurrency.analyzers.base import BaseConcurrencyAnalyzer
from python_hunter.domain.concurrency.models import ConcurrencyContext, ExecutionModel


class AsyncAnalyzer(BaseConcurrencyAnalyzer):
    """Analyzes async def, await points, Task creation, gather, wait, TaskGroup, and background tasks."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        contexts: list[ConcurrencyContext] = []
        metadata_events: list[dict[str, Any]] = []

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                line = getattr(node, "lineno", 1)
                loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                # 1. Async Function Def
                if isinstance(node, ast.AsyncFunctionDef):
                    contexts.append(
                        ConcurrencyContext(
                            context_id=f"{doc.file_path}:{node.name}:{line}",
                            execution_model=ExecutionModel.ASYNC_TASK,
                            name=node.name,
                            file_path=doc.file_path,
                            location=loc,
                            metadata={"is_coroutine": True},
                        )
                    )

                # 2. Await Expression Boundaries
                elif isinstance(node, ast.Await):
                    metadata_events.append({
                        "type": "await_point",
                        "file_path": doc.file_path,
                        "location": loc,
                    })

                # 3. Call Expressions (create_task, gather, TaskGroup)
                elif isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    if func_name in ("create_task", "ensure_future", "Task"):
                        contexts.append(
                            ConcurrencyContext(
                                context_id=f"{doc.file_path}:task:{line}",
                                execution_model=ExecutionModel.ASYNC_TASK,
                                name="asyncio_task",
                                file_path=doc.file_path,
                                location=loc,
                                metadata={"spawned_by": func_name},
                            )
                        )
                    elif func_name in ("gather", "wait", "as_completed"):
                        metadata_events.append({
                            "type": "concurrent_group",
                            "func_name": func_name,
                            "file_path": doc.file_path,
                            "location": loc,
                        })

        return {
            "contexts": contexts,
            "events": metadata_events,
        }
