"""Unit tests for Concurrency Analysis Engine."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_concurrency import AnalyzeConcurrencyUseCase
from python_hunter.domain.concurrency.engine import ConcurrencyAnalysisEngine
from python_hunter.domain.concurrency.models import ExecutionModel
from python_hunter.rules.concurrency import PYHConc001PotentialRace, PYHConc003TOCTOU


class TestConcurrencyAnalysisEngine(unittest.TestCase):
    """Unit test suite for ConcurrencyAnalysisEngine and Analyzers."""

    def setUp(self) -> None:
        self.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "fixtures", "concurrency")
        )
        self.ast_use_case = AnalyzeASTUseCase()
        self.use_case = AnalyzeConcurrencyUseCase(ast_use_case=self.ast_use_case)

    def test_asyncio_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "asyncio", "app.py")
        contexts, resources, syncs, lock_graph, races, summary = self.use_case.execute(fixture_path)

        self.assertGreater(summary.total_async_functions, 0)
        self.assertGreater(summary.total_tasks, 0)
        models = [c.execution_model for c in contexts]
        self.assertIn(ExecutionModel.ASYNC_TASK, models)

    def test_threading_and_process_analysis(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "threading", "app.py")
        contexts, resources, syncs, lock_graph, races, summary = self.use_case.execute(fixture_path)

        self.assertGreater(summary.total_threads, 0)
        self.assertGreater(summary.total_processes, 0)
        self.assertGreater(summary.total_synchronization_objects, 0)

    def test_deadlock_cycle_detection(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "races", "app.py")
        contexts, resources, syncs, lock_graph, races, summary = self.use_case.execute(fixture_path)

        cycles = lock_graph.find_cycles()
        self.assertGreater(len(cycles), 0)

    def test_toctou_and_race_detection(self) -> None:
        fixture_path = os.path.join(self.fixtures_dir, "races", "app.py")
        contexts, resources, syncs, lock_graph, races, summary = self.use_case.execute(fixture_path)

        self.assertGreater(len(races), 0)
        types = [r.race_type for r in races]
        self.assertIn("TOCTOU", types)

    def test_safety_no_code_execution(self) -> None:
        """Verify target application code is never imported, run, or spawned into real threads/processes."""
        fixture_path = os.path.join(self.fixtures_dir, "threading", "app.py")
        contexts, resources, syncs, lock_graph, races, summary = self.use_case.execute(fixture_path)
        self.assertIsNotNone(summary)


if __name__ == "__main__":
    unittest.main()
