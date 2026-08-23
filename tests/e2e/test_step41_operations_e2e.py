"""End-to-End Test Suite for Step 41 Autonomous Security Operations & Continuous Monitoring."""

import hashlib
import hmac
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.operations.alerts import AlertType, AlertStatus
from python_hunter.domain.operations.events import SecurityEvent, SecurityEventType
from python_hunter.domain.operations.health import HealthState
from python_hunter.domain.operations.queue import JobType, JobStatus
from python_hunter.domain.operations.scheduler import MonitoredRepository


class TestStep41OperationsE2E(unittest.TestCase):
    """End-to-end tests validating autonomous continuous security operations."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_e2e_webhook_to_job_queue_pipeline(self) -> None:
        """Test incoming webhook event validation, event bus publish, job queueing, and worker processing."""
        raw_body = b'{"repository": "kayinamura-karimba-geofrey/python-hunter", "ref": "refs/heads/main"}'
        sig = hmac.new(b"pyh_webhook_secret_key", raw_body, hashlib.sha256).hexdigest()

        # Validate signature
        is_valid = self.app_service.webhook_validator.validate_signature(raw_body, f"sha256={sig}")
        self.assertTrue(is_valid)

        # Publish event
        evt = SecurityEvent(
            event_id="evt-push-101",
            event_type=SecurityEventType.COMMIT_CREATED,
            source="github_webhook",
            repository="kayinamura-karimba-geofrey/python-hunter",
            commit="a1b2c3d",
        )
        published = self.app_service.event_bus.publish(evt)
        self.assertTrue(published)

        # Enqueue Job
        job = self.app_service.job_queue.enqueue(
            job_id="job-scan-101",
            job_type=JobType.INCREMENTAL_SCAN,
            repository="kayinamura-karimba-geofrey/python-hunter",
            payload={"commit": "a1b2c3d"},
        )
        self.assertEqual(job.status, JobStatus.QUEUED)

        # Register & Process Job with Worker
        processed_jobs = []
        self.app_service.worker.register_handler(
            JobType.INCREMENTAL_SCAN, lambda j: processed_jobs.append(j.job_id)
        )
        self.app_service.worker.process_one()

        self.assertEqual(len(processed_jobs), 1)
        self.assertEqual(processed_jobs[0], "job-scan-101")
        self.assertEqual(job.status, JobStatus.COMPLETED)

    def test_e2e_alert_to_incident_and_notification(self) -> None:
        """Test creating alerts, deduplication, notification dispatch, and incident correlation."""
        # Create 2 related alerts
        a1 = self.app_service.alert_engine.create_or_deduplicate_alert(
            alert_id="ALT-201",
            severity=Severity.CRITICAL,
            alert_type=AlertType.CRITICAL_VULNERABILITY,
            source="IntelligenceEngine",
            repository="kayinamura-karimba-geofrey/python-hunter",
            title="Critical Vuln in Requests",
            description="Vulnerable HTTP library version.",
            finding_id="FIND-1",
        )
        a2 = self.app_service.alert_engine.create_or_deduplicate_alert(
            alert_id="ALT-202",
            severity=Severity.HIGH,
            alert_type=AlertType.SECRET_EXPOSURE,
            source="SecretsEngine",
            repository="kayinamura-karimba-geofrey/python-hunter",
            title="AWS Access Key Exposed",
            description="Active AWS key found in git commit.",
            finding_id="FIND-2",
        )

        # Dispatch notification
        dispatched = self.app_service.notification_registry.dispatch(a1)
        self.assertGreaterEqual(dispatched, 1)

        # Correlate into incident
        alerts = self.app_service.alert_engine.get_open_alerts()
        incidents = self.app_service.incident_engine.correlate_alerts(alerts)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, Severity.CRITICAL)
        self.assertEqual(len(incidents[0].alerts), 2)

    def test_e2e_continuous_scheduler_and_health(self) -> None:
        """Test scheduler repository monitoring registration and platform health reporting."""
        repo = MonitoredRepository(repository="kayinamura-karimba-geofrey/python-hunter", branch="main")
        self.app_service.scheduler.register_repository(repo)

        pending = self.app_service.scheduler.get_pending_scheduled_jobs()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["repository"], "kayinamura-karimba-geofrey/python-hunter")

        health = self.app_service.health_monitor.to_dict()
        self.assertEqual(health["status"], "HEALTHY")


if __name__ == "__main__":
    unittest.main()
