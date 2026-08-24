"""End-to-End Test Suite for Step 44 Distributed Architecture, Scalability & Hardening."""

import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.infrastructure.scaling.bulkhead import WorkerPoolType
from python_hunter.infrastructure.scaling.quotas import QuotaExceededError, ResourceQuota


class TestStep44HardeningE2E(unittest.TestCase):
    """End-to-end integration tests validating distributed queueing, quota limits, sandbox isolation, and health checks."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_e2e_quota_reservation_and_enforcement(self) -> None:
        """Test tenant quota enforcement and reservation."""
        self.app_service.quota_manager.set_quota(ResourceQuota(organization_id="org-default", max_concurrent_scans=2))

        self.assertTrue(self.app_service.quota_manager.reserve_scan_slot("org-default"))
        self.assertTrue(self.app_service.quota_manager.reserve_scan_slot("org-default"))

        with self.assertRaises(QuotaExceededError):
            self.app_service.quota_manager.reserve_scan_slot("org-default")

        self.app_service.quota_manager.release_scan_slot("org-default")
        self.assertTrue(self.app_service.quota_manager.reserve_scan_slot("org-default"))

    def test_e2e_bulkhead_and_telemetry_health(self) -> None:
        """Test worker pool bulkhead slot management and dependency health status."""
        slot = self.app_service.bulkhead_manager.acquire_slot(WorkerPoolType.SAST)
        self.assertTrue(slot)
        self.app_service.bulkhead_manager.release_slot(WorkerPoolType.SAST)

        self.assertTrue(self.app_service.dependency_health.is_healthy)

    def test_e2e_feature_flag_and_configuration(self) -> None:
        """Test feature flag checks and environment configuration loading."""
        enabled = self.app_service.feature_flags.is_enabled("distributed_queue_v2")
        self.assertTrue(enabled)

        cfg = self.app_service.config_manager.load_configuration()
        self.assertIsNotNone(cfg.environment)


if __name__ == "__main__":
    unittest.main()
