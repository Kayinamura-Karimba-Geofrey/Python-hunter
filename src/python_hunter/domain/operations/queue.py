"""Security Job Queue, Priority Scheduler, Worker System, and Dead Letter Queue."""

import heapq
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class JobStatus(str, Enum):
    """Job execution states."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    RETRYING = "RETRYING"


class JobType(str, Enum):
    """Supported job execution types."""

    REPOSITORY_SCAN = "repository_scan"
    INCREMENTAL_SCAN = "incremental_scan"
    DEPENDENCY_REFRESH = "dependency_refresh"
    INTELLIGENCE_REFRESH = "intelligence_refresh"
    ATTACK_PATH_RECALCULATION = "attack_path_recalculation"
    POSTURE_RECALCULATION = "posture_recalculation"
    POLICY_EVALUATION = "policy_evaluation"
    REPORT_GENERATION = "report_generation"


@dataclass(order=True)
class SecurityJob:
    """Security Job with priority queue ordering."""

    priority: int  # Lower number = higher priority
    job_id: str = field(compare=False)
    job_type: JobType = field(compare=False)
    repository: str = field(compare=False)
    payload: dict[str, Any] = field(default_factory=dict, compare=False)
    status: JobStatus = field(default=JobStatus.QUEUED, compare=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc), compare=False)
    started_at: datetime | None = field(default=None, compare=False)
    completed_at: datetime | None = field(default=None, compare=False)
    max_retries: int = field(default=3, compare=False)
    retry_count: int = field(default=0, compare=False)
    error_message: str | None = field(default=None, compare=False)


class DeadLetterQueue:
    """Stores failed jobs exceeding retry limits for investigation."""

    def __init__(self) -> None:
        self._dead_jobs: list[SecurityJob] = []

    def add(self, job: SecurityJob) -> None:
        self._dead_jobs.append(job)

    def list_jobs(self) -> list[SecurityJob]:
        return list(self._dead_jobs)


class SecurityJobQueue:
    """Priority Job Queue managing concurrency, retries, and dead-letter handling."""

    PRIORITY_MAP = {
        JobType.INCREMENTAL_SCAN: 1,  # Highest priority for active PRs/commits
        JobType.ATTACK_PATH_RECALCULATION: 2,
        JobType.REPOSITORY_SCAN: 3,
        JobType.POLICY_EVALUATION: 4,
        JobType.INTELLIGENCE_REFRESH: 5,
        JobType.POSTURE_RECALCULATION: 6,
        JobType.DEPENDENCY_REFRESH: 7,
        JobType.REPORT_GENERATION: 8,
    }

    def __init__(self) -> None:
        self._heap: list[SecurityJob] = []
        self.dead_letter_queue = DeadLetterQueue()
        self._all_jobs: dict[str, SecurityJob] = {}

    def enqueue(self, job_id: str, job_type: JobType, repository: str, payload: dict[str, Any] | None = None) -> SecurityJob:
        """Enqueue new job into priority heap."""
        priority = self.PRIORITY_MAP.get(job_type, 5)
        job = SecurityJob(
            priority=priority,
            job_id=job_id,
            job_type=job_type,
            repository=repository,
            payload=payload or {},
        )
        heapq.heappush(self._heap, job)
        self._all_jobs[job_id] = job
        return job

    def pop_next(self) -> SecurityJob | None:
        """Pop highest priority job from queue."""
        if self._heap:
            job = heapq.heappop(self._heap)
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            return job
        return None

    def handle_job_failure(self, job: SecurityJob, error: Exception) -> None:
        """Handle job failure with exponential backoff retries or dead-letter placement."""
        job.error_message = str(error)
        if job.retry_count < job.max_retries:
            job.retry_count += 1
            job.status = JobStatus.RETRYING
            # Re-enqueue job
            heapq.heappush(self._heap, job)
        else:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            self.dead_letter_queue.add(job)

    def mark_completed(self, job: SecurityJob) -> None:
        """Mark job as successfully completed."""
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)

    def list_all(self) -> list[SecurityJob]:
        return list(self._all_jobs.values())


class SecurityWorker:
    """Worker system processing jobs independently from priority queue."""

    def __init__(self, queue: SecurityJobQueue) -> None:
        self.queue = queue
        self._handlers: dict[JobType, Callable[[SecurityJob], None]] = {}

    def register_handler(self, job_type: JobType, handler: Callable[[SecurityJob], None]) -> None:
        self._handlers[job_type] = handler

    def process_one(self) -> bool:
        """Process next available job in queue."""
        job = self.queue.pop_next()
        if not job:
            return False

        handler = self._handlers.get(job.job_type)
        if not handler:
            self.queue.mark_completed(job)
            return True

        try:
            handler(job)
            self.queue.mark_completed(job)
        except Exception as e:
            self.queue.handle_job_failure(job, e)

        return True
