"""Security Event model and SecurityEventBus for continuous security operations."""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class SecurityEventType(str, Enum):
    """Supported security event types in platform."""

    REPOSITORY_CREATED = "repository_created"
    REPOSITORY_UPDATED = "repository_updated"
    COMMIT_CREATED = "commit_created"
    PULL_REQUEST_OPENED = "pull_request_opened"
    PULL_REQUEST_UPDATED = "pull_request_updated"
    PULL_REQUEST_MERGED = "pull_request_merged"
    DEPENDENCY_CHANGED = "dependency_changed"
    VULNERABILITY_PUBLISHED = "vulnerability_published"
    VULNERABILITY_UPDATED = "vulnerability_updated"
    SECRET_DETECTED = "secret_detected"
    INFRASTRUCTURE_CHANGED = "infrastructure_changed"
    CONTAINER_CHANGED = "container_changed"
    POLICY_CHANGED = "policy_changed"
    FINDING_CREATED = "finding_created"
    FINDING_RESOLVED = "finding_resolved"
    ATTACK_PATH_CREATED = "attack_path_created"
    ATTACK_PATH_RESOLVED = "attack_path_resolved"


@dataclass
class SecurityEvent:
    """Canonical security event data structure."""

    event_id: str
    event_type: SecurityEventType
    source: str  # e.g. github_webhook, scheduler, fs_monitor, manual
    repository: str
    branch: str = "main"
    commit: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def deduplication_hash(self) -> str:
        """Generate deterministic hash for event deduplication."""
        raw = f"{self.event_type.value}:{self.source}:{self.repository}:{self.branch}:{self.commit or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SecurityEventBus:
    """Central event bus supporting event publishing, subscription, deduplication, and replay protection."""

    def __init__(self, deduplication_window_seconds: int = 300) -> None:
        self._subscribers: dict[SecurityEventType, list[Callable[[SecurityEvent], None]]] = {}
        self._seen_event_hashes: dict[str, float] = {}
        self._dedup_window = deduplication_window_seconds
        self._event_history: list[SecurityEvent] = []

    def subscribe(self, event_type: SecurityEventType, handler: Callable[[SecurityEvent], None]) -> None:
        """Subscribe handler to a specific event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def publish(self, event: SecurityEvent) -> bool:
        """Publish security event to subscribers if not duplicate."""
        now = time.time()
        dedup_hash = event.deduplication_hash

        # Event deduplication check
        if dedup_hash in self._seen_event_hashes:
            last_seen = self._seen_event_hashes[dedup_hash]
            if now - last_seen < self._dedup_window:
                # Duplicate event within window -> drop
                return False

        self._seen_event_hashes[dedup_hash] = now
        self._event_history.append(event)

        # Notify subscribers
        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass

        return True

    def get_event_history(self) -> list[SecurityEvent]:
        """Return full immutable event history log."""
        return list(self._event_history)
