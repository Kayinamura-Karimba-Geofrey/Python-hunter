"""Thread and Process Concurrency Analyzer."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.concurrency.analyzers.base import BaseConcurrencyAnalyzer
from python_hunter.domain.concurrency.models import ConcurrencyContext, ExecutionModel


class ThreadProcessAnalyzer(BaseConcurrencyAnalyzer):
    """Analyzes threading.Thread, ThreadPoolExecutor, multiprocessing.Process, ProcessPoolExecutor."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, list[Any]]:
        contexts: list[ConcurrencyContext] = []

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

                    if func_name == "Thread" or (mod_name == "threading" and func_name == "Thread"):
                        contexts.append(
                            ConcurrencyContext(
                                context_id=f"{doc.file_path}:thread:{line}",
                                execution_model=ExecutionModel.THREAD,
                                name="thread",
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )
                    elif func_name == "ThreadPoolExecutor":
                        contexts.append(
                            ConcurrencyContext(
                                context_id=f"{doc.file_path}:threadpool:{line}",
                                execution_model=ExecutionModel.EXECUTOR,
                                name="thread_pool_executor",
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )
                    elif func_name == "Process" or (mod_name == "multiprocessing" and func_name == "Process"):
                        contexts.append(
                            ConcurrencyContext(
                                context_id=f"{doc.file_path}:process:{line}",
                                execution_model=ExecutionModel.PROCESS,
                                name="process",
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )
                    elif func_name == "ProcessPoolExecutor":
                        contexts.append(
                            ConcurrencyContext(
                                context_id=f"{doc.file_path}:processpool:{line}",
                                execution_model=ExecutionModel.EXECUTOR,
                                name="process_pool_executor",
                                file_path=doc.file_path,
                                location=loc,
                            )
                        )

        return {"contexts": contexts}
