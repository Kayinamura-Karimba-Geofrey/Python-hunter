"""Asynchronous Webhook Event Queue & Job Processor with Dead Letter Queue handling."""

import logging
import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("python_hunter.webhook_queue")


@dataclass
class WebhookJob:
    job_id: str
    delivery_id: str
    event_type: str
    payload: Dict[str, Any]
    status: str = "QUEUED"  # QUEUED, IN_PROGRESS, COMPLETED, FAILED, DEAD_LETTER
    attempts: int = 0
    max_attempts: int = 3
    error_message: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class GitHubWebhookEventQueue:
    """In-memory asynchronous event queue with bounded retries and dead letter queue."""

    def __init__(self) -> None:
        self.jobs: Dict[str, WebhookJob] = {}
        self.dead_letter_queue: List[WebhookJob] = []
        self._work_queue: queue.Queue = queue.Queue()
        self._pr_active_jobs: Dict[str, str] = {}  # Map repo#pr -> latest job_id

    def enqueue_event(self, delivery_id: str, event_type: str, payload: Dict[str, Any]) -> WebhookJob:
        """Enqueues an incoming webhook event for background processing."""
        job_id = str(uuid.uuid4())
        job = WebhookJob(
            job_id=job_id,
            delivery_id=delivery_id,
            event_type=event_type,
            payload=payload,
        )
        self.jobs[job_id] = job

        # Race condition & cancellation handling for PRs:
        # If a new PR commit arrives while an old job is queued/in progress, mark older job obsolete
        if event_type == "pull_request":
            pr_data = payload.get("pull_request", {})
            repo = payload.get("repository", {}).get("full_name", "")
            pr_num = pr_data.get("number")
            if repo and pr_num:
                pr_key = f"{repo}#{pr_num}"
                prev_job_id = self._pr_active_jobs.get(pr_key)
                if prev_job_id and prev_job_id in self.jobs:
                    prev_job = self.jobs[prev_job_id]
                    if prev_job.status in ("QUEUED", "IN_PROGRESS"):
                        logger.info(f"Superseding obsolete scan job {prev_job_id} with newer PR commit job {job_id}")
                        prev_job.status = "OBSOLETE"
                self._pr_active_jobs[pr_key] = job_id

        self._work_queue.put(job)
        return job

    def process_next(self, handler_fn) -> Optional[WebhookJob]:
        """Processes the next job in the queue using the provided handler_fn."""
        try:
            job: WebhookJob = self._work_queue.get_nowait()
        except queue.Empty:
            return None

        if job.status == "OBSOLETE":
            logger.info(f"Skipping obsolete job {job.job_id}")
            self._work_queue.task_done()
            return job

        job.status = "IN_PROGRESS"
        job.attempts += 1

        try:
            handler_fn(job)
            job.status = "COMPLETED"
        except Exception as e:
            logger.error(f"Error processing webhook job {job.job_id}: {e}")
            job.error_message = str(e)
            if job.attempts < job.max_attempts:
                job.status = "QUEUED"
                logger.info(f"Retrying job {job.job_id} (Attempt {job.attempts}/{job.max_attempts})")
                self._work_queue.put(job)
            else:
                job.status = "DEAD_LETTER"
                self.dead_letter_queue.append(job)
                logger.error(f"Job {job.job_id} moved to Dead Letter Queue after {job.attempts} attempts.")
        finally:
            self._work_queue.task_done()

        return job

    def get_status_summary(self) -> Dict[str, Any]:
        """Returns metrics on webhook event processing status."""
        total = len(self.jobs)
        completed = sum(1 for j in self.jobs.values() if j.status == "COMPLETED")
        failed = sum(1 for j in self.jobs.values() if j.status == "FAILED")
        dead_letter = len(self.dead_letter_queue)
        queued = sum(1 for j in self.jobs.values() if j.status in ("QUEUED", "IN_PROGRESS"))

        return {
            "total_events": total,
            "queued": queued,
            "completed": completed,
            "failed": failed,
            "dead_letter_count": dead_letter,
            "webhook_active": True,
        }
