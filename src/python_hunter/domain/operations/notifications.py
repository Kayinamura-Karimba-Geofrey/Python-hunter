"""Notification Registry, Providers, Secret Redaction, and Digest Routing."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from python_hunter.domain.operations.alerts import SecurityAlert


class NotificationProvider(ABC):
    """Abstract provider for sending security alerts without exposing raw secrets or code."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def send_notification(self, alert: SecurityAlert, recipient: str | None = None) -> bool:
        pass


class MockSlackNotificationProvider(NotificationProvider):
    """Mock Slack Notification Provider with secret redaction."""

    def __init__(self, channel: str = "#security-alerts") -> None:
        self.channel = channel
        self.sent_messages: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "Slack"

    def send_notification(self, alert: SecurityAlert, recipient: str | None = None) -> bool:
        # Sanitize alert content - redact any potential secrets
        safe_desc = alert.description.replace("SECRET", "[REDACTED_SECRET]")
        target_channel = recipient or self.channel
        msg = {
            "channel": target_channel,
            "title": f"[{alert.severity.value}] {alert.title}",
            "text": safe_desc,
            "repository": alert.repository,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.sent_messages.append(msg)
        return True


class NotificationRegistry:
    """Notification Provider Registry with routing rules and digest management."""

    def __init__(self) -> None:
        self._providers: dict[str, NotificationProvider] = {}
        self._enabled: dict[str, bool] = {}

    def register(self, provider: NotificationProvider, enabled: bool = True) -> None:
        self._providers[provider.name] = provider
        self._enabled[provider.name] = enabled

    def dispatch(self, alert: SecurityAlert, routing_rules: dict[str, str] | None = None) -> int:
        """Route alert to appropriate active notification provider based on policy."""
        dispatched_count = 0
        for name, provider in self._providers.items():
            if self._enabled.get(name, False):
                recipient = routing_rules.get(alert.severity.value) if routing_rules else None
                if provider.send_notification(alert, recipient=recipient):
                    dispatched_count += 1
        return dispatched_count
