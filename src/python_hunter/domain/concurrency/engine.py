"""Concurrency Analysis Orchestration Engine Implementation."""

import logging
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.concurrency.analyzers import (
    AsyncAnalyzer,
    BaseConcurrencyAnalyzer,
    RaceConditionAnalyzer,
    SharedStateAnalyzer,
    SynchronizationAnalyzer,
    ThreadProcessAnalyzer,
)
from python_hunter.domain.concurrency.models import (
    ConcurrencyContext,
    ConcurrencySummary,
    LockOrderGraph,
    RaceCandidate,
    SharedResource,
    SynchronizationObject,
)

logger = logging.getLogger(__name__)


class ConcurrencyAnalysisEngine:
    """Orchestrates static concurrency, async, thread, process, lock, and race condition analysis."""

    def __init__(self, mode: str = "balanced") -> None:
        self.mode = mode  # conservative, balanced, aggressive
        self.analyzers: list[BaseConcurrencyAnalyzer] = [
            AsyncAnalyzer(),
            ThreadProcessAnalyzer(),
            SharedStateAnalyzer(),
            SynchronizationAnalyzer(),
            RaceConditionAnalyzer(),
        ]

    def analyze(
        self, documents: list[ASTDocument]
    ) -> tuple[
        list[ConcurrencyContext],
        list[SharedResource],
        list[SynchronizationObject],
        LockOrderGraph,
        list[RaceCandidate],
        ConcurrencySummary,
    ]:
        """Statically analyze documents for concurrency behaviors and security risks."""
        all_contexts: list[ConcurrencyContext] = []
        all_resources: list[SharedResource] = []
        all_syncs: list[SynchronizationObject] = []
        lock_graph = LockOrderGraph()
        all_races: list[RaceCandidate] = []

        for analyzer in self.analyzers:
            res = analyzer.analyze(documents)
            if "contexts" in res:
                all_contexts.extend(res["contexts"])
            if "resources" in res:
                all_resources.extend(res["resources"])
            if "sync_objects" in res:
                all_syncs.extend(res["sync_objects"])
            if "lock_graph" in res:
                g: LockOrderGraph = res["lock_graph"]
                lock_graph.nodes.update(g.nodes)
                lock_graph.edges.extend(g.edges)
            if "races" in res:
                all_races.extend(res["races"])

        # Detect deadlock cycles from LockOrderGraph
        deadlock_cycles = lock_graph.find_cycles()

        # Build statistical summary
        summary = ConcurrencySummary(
            total_async_functions=sum(1 for c in all_contexts if c.metadata.get("is_coroutine")),
            total_tasks=sum(1 for c in all_contexts if c.name == "asyncio_task"),
            total_threads=sum(1 for c in all_contexts if c.name in ("thread", "thread_pool_executor")),
            total_processes=sum(1 for c in all_contexts if c.name in ("process", "process_pool_executor")),
            total_shared_resources=len(all_resources),
            total_synchronization_objects=len(all_syncs),
            total_race_candidates=len(all_races),
            total_deadlock_candidates=len(deadlock_cycles),
            security_races_count=sum(1 for r in all_races if r.is_security_sensitive),
        )

        return all_contexts, all_resources, all_syncs, lock_graph, all_races, summary
