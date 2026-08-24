"""Minimal Unit tests for Step 44 Infrastructure Modules."""

import os
import unittest

from python_hunter.infrastructure.scaling.bulkhead import BulkheadManager, WorkerPoolType
from python_hunter.infrastructure.scaling.locks import LockManager
from python_hunter.infrastructure.scaling.sandboxing import ScannerSandbox
from python_hunter.infrastructure.storage.cache import CacheAbstraction
from python_hunter.infrastructure.storage.search import ScalableSearchEngine
from python_hunter.infrastructure.telemetry.logging import StructuredLogger


class TestDistributedScalingUnit(unittest.TestCase):

    def test_distributed_lock_recovery(self) -> None:
        lock_mgr = LockManager()
        self.assertTrue(lock_mgr.acquire_lock("repo-1", owner_id="worker-1", ttl_seconds=1))
        self.assertFalse(lock_mgr.acquire_lock("repo-1", owner_id="worker-2", ttl_seconds=1))

    def test_bulkhead_worker_pool_capacity(self) -> None:
        bm = BulkheadManager()
        bm.DEFAULT_CAPACITIES[WorkerPoolType.CONTAINERS] = 1

        self.assertTrue(bm.acquire_slot(WorkerPoolType.CONTAINERS))
        self.assertFalse(bm.acquire_slot(WorkerPoolType.CONTAINERS))
        bm.release_slot(WorkerPoolType.CONTAINERS)
        self.assertTrue(bm.acquire_slot(WorkerPoolType.CONTAINERS))

    def test_sandbox_workspace_cleanup(self) -> None:
        with ScannerSandbox() as box:
            temp_path = box.temp_dir
            self.assertIsNotNone(temp_path)
            self.assertTrue(os.path.exists(temp_path))

        self.assertFalse(os.path.exists(temp_path))

    def test_structured_logging_secret_redaction(self) -> None:
        logger = StructuredLogger()
        log_entry = logger.log("info", "Scan started with token SECRET_API_KEY_123", organization_id="org-1")
        self.assertNotIn("SECRET_API_KEY_123", log_entry)
        self.assertIn("[REDACTED]", log_entry)

    def test_cursor_pagination(self) -> None:
        engine = ScalableSearchEngine()
        findings = [{"id": f"FIND-{i}", "severity": "HIGH"} for i in range(25)]
        page1 = engine.search_findings(findings, cursor=0, limit=10)

        self.assertEqual(len(page1.items), 10)
        self.assertTrue(page1.has_more)
        self.assertEqual(page1.next_cursor, "10")


if __name__ == "__main__":
    unittest.main()
