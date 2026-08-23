"""Unit tests for Step 41 Autonomous Security Operations & Continuous Monitoring."""

import unittest
from datetime import datetime, timezone

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.operations.alerts import AlertEngine, AlertStatus, AlertType, SecurityAlert
from python_hunter.domain.operations.events import SecurityEvent, SecurityEventBus, SecurityEventType
from python_hunter.domain.operations.health import HealthState, SecurityPlatformHealth
from python_hunter.domain.operations.incidents import IncidentCorrelationEngine, IncidentStatus
from python_hunter.domain.operations.incremental import ChangeImpactEngine, SecurityDriftEngine
from python_hunter.domain.operations.notifications import MockSlackNotificationProvider, NotificationRegistry
from python_hunter.domain.operations.queue import DeadLetterQueue, JobStatus, JobType, SecurityJobQueue, SecurityWorker
from python_hunter.domain.operations.scheduler import MonitoredRepository, SecurityScheduler
from python_hunter.infrastructure.operations.webhooks import AuditLogger, GitHubWebhookValidator


class TestOperationsEngineUnit(unittest.TestCase):
    """Unit tests for operations domain engines."""

    def test_security_event_bus_deduplication(self) -> None:
        bus = SecurityEventBus(deduplication_window_seconds=10)
        evt1 = SecurityEvent(
            event_id="EVT-1",
            event_type=SecurityEventType.PULL_REQUEST_OPENED,
            source="github_webhook",
            repository="repo-a",
            branch="feature",
            commit="c111",
        )
        evt2 = SecurityEvent(
            event_id="EVT-2",
            event_type=SecurityEventType.PULL_REQUEST_OPENED,
            source="github_webhook",
            repository="repo-a",
            branch="feature",
            commit="c111",
        )

        res1 = bus.publish(evt1)
        res2 = bus.publish(evt2)

        self.assertTrue(res1)
        self.assertFalse(res2)  # Duplicate dropped
        self.assertEqual(len(bus.get_event_history()), 1)

    def test_job_queue_priority_and_worker(self) -> None:
        queue = SecurityJobQueue()
        queue.enqueue("j1", JobType.REPORT_GENERATION, "repo-a")
        queue.enqueue("j2", JobType.INCREMENTAL_SCAN, "repo-a")

        worker = SecurityWorker(queue)
        executed = []

        def handle_job(job):
            executed.append(job.job_id)

        worker.register_handler(JobType.INCREMENTAL_SCAN, handle_job)
        worker.register_handler(JobType.REPORT_GENERATION, handle_job)

        worker.process_one()
        self.assertEqual(executed[0], "j2")  # Incremental scan has higher priority than report generation

    def test_job_retry_and_dead_letter_queue(self) -> None:
        queue = SecurityJobQueue()
        job = queue.enqueue("failing-job", JobType.REPOSITORY_SCAN, "repo-b")
        job.max_retries = 1

        def fail_handler(j):
            raise ValueError("Scan Error")

        worker = SecurityWorker(queue)
        worker.register_handler(JobType.REPOSITORY_SCAN, fail_handler)

        worker.process_one()  # First attempt fails -> retry state
        self.assertEqual(job.status, JobStatus.RETRYING)

        worker.process_one()  # Retry fails -> dead letter queue
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertEqual(len(queue.dead_letter_queue.list_jobs()), 1)

    def test_change_impact_engine(self) -> None:
        engine = ChangeImpactEngine()
        scope = engine.calculate_impact("repo-c", changed_files=["src/auth/login.py"], dependency_manifest_changed=False)
        self.assertIn("authenticate_user", scope.affected_functions)
        self.assertFalse(scope.requires_full_rescan)

    def test_alert_engine_deduplication_and_fatigue(self) -> None:
        engine = AlertEngine()
        a1 = engine.create_or_deduplicate_alert(
            "alt-1", Severity.HIGH, AlertType.CRITICAL_VULNERABILITY, "intel", "repo-d", "Vuln 1", "Desc 1", finding_id="f1"
        )
        a2 = engine.create_or_deduplicate_alert(
            "alt-2", Severity.CRITICAL, AlertType.CRITICAL_VULNERABILITY, "intel", "repo-d", "Vuln 1", "Desc 1", finding_id="f1"
        )

        self.assertEqual(len(engine.alerts), 1)
        self.assertEqual(a1.severity, Severity.CRITICAL)  # Escalated severity

    def test_incident_correlation(self) -> None:
        engine = AlertEngine()
        a1 = engine.create_or_deduplicate_alert("alt-1", Severity.CRITICAL, AlertType.CRITICAL_VULNERABILITY, "source", "repo-e", "Vuln", "Desc", finding_id="f1")
        a2 = engine.create_or_deduplicate_alert("alt-2", Severity.HIGH, AlertType.SECRET_EXPOSURE, "source", "repo-e", "Secret", "Desc", finding_id="f2")

        inc_engine = IncidentCorrelationEngine()
        incidents = inc_engine.correlate_alerts([a1, a2])

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, Severity.CRITICAL)
        self.assertEqual(len(incidents[0].alerts), 2)

    def test_webhook_validator_signature(self) -> None:
        validator = GitHubWebhookValidator(secret="my_secret")
        payload = b'{"ref": "refs/heads/main"}'
        import hashlib
        import hmac

        sig = hmac.new(b"my_secret", payload, hashlib.sha256).hexdigest()

        self.assertTrue(validator.validate_signature(payload, f"sha256={sig}"))
        self.assertFalse(validator.validate_signature(payload, "sha256=invalid"))


if __name__ == "__main__":
    unittest.main()
