"""Priority Distributed Job Queue, Lifecycle States, Retries with Backoff & DLQ."""

import heapq
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any


class JobState(str, Enum):
    """Lifecycle states of distributed jobs."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    RETRYING = "RETRYING"


class JobPriority(IntEnum):
    """Priority level for job scheduling."""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


@dataclass(order=True)
class PriorityJob:
    """Job container ordered by priority and creation timestamp."""

    priority: JobPriority
    created_timestamp: float
    job_id: str = field(compare=False)
    organization_id: str = field(compare=False)
    job_type: str = field(compare=False)
    payload: dict[str, Any] = field(compare=False)
    state: JobState = field(default=JobState.CREATED, compare=False)
    attempts: int = field(default=0, compare=False)
    max_attempts: int = field(default=3, compare=False)
    timeout_seconds: int = field(default=600, compare=False)
    error_message: str | None = field(default=None, compare=False)


class DeadLetterQueue:
    """Dead Letter Queue holding failed jobs for administrative replay."""

    def __init__(self) -> None:
        self._dlq_store: dict[str, PriorityJob] = {}

    def push(self, job: PriorityJob) -> None:
        job.state = JobState.FAILED
        self._dlq_store[job.job_id] = job

    def list_jobs(self) -> list[PriorityJob]:
        return list(self._dlq_store.values())

    def pop(self, job_id: str) -> PriorityJob | None:
        return self._dlq_store.pop(job_id, None)


class PriorityJobQueue:
    """Thread-safe priority job queue supporting jitter retries and job cancellation."""

    def __init__(self) -> None:
        self._heap: list[PriorityJob] = []
        self._jobs: dict[str, PriorityJob] = {}
        self.dlq = DeadLetterQueue()
        self._lock = threading.Lock()

    def enqueue(self, job: PriorityJob) -> None:
        with self._lock:
            job.state = JobState.QUEUED
            self._jobs[job.job_id] = job
            heapq.heappush(self._heap, job)

    def dequeue(self) -> PriorityJob | None:
        with self._lock:
            while self._heap:
                job = heapq.heappop(self._heap)
                if job.state == JobState.CANCELLED:
                    continue
                job.state = JobState.RUNNING
                return job
            return None

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.state in (JobState.CREATED, JobState.QUEUED):
                job.state = JobState.CANCELLED
                return True
            return False

    def handle_failure(self, job: PriorityJob, error: str) -> None:
        with self._lock:
            job.attempts += 1
            job.error_message = error
            if job.attempts < job.max_attempts:
                job.state = JobState.RETRYING
                # Exponential backoff with jitter
                delay = (2 ** job.attempts) + random.uniform(0.1, 1.0)
                job.created_timestamp = time.time() + delay
                heapq.heappush(self._heap, job)
            else:
                self.dlq.push(job)
