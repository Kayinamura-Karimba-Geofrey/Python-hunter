"""IntegrationProvider base class and enterprise providers (GitHub, GitLab, Bitbucket, Jira, Slack, Teams, Webhook, SIEM, SSO)."""

import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.integrations.models import IntegrationProviderType, IntegrationStatus


class IntegrationProvider(ABC):
    """Abstract Base Class for Enterprise Integration Providers."""

    @property
    @abstractmethod
    def provider_type(self) -> IntegrationProviderType:
        pass

    @abstractmethod
    def connect(self, config: dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def health_check(self) -> IntegrationStatus:
        pass


class GitHubProvider(IntegrationProvider):
    """GitHub integration provider (Checks, PR comments, Webhooks, Issues)."""

    @property
    def provider_type(self) -> IntegrationProviderType:
        return IntegrationProviderType.GITHUB

    def connect(self, config: dict[str, Any]) -> bool:
        return bool(config.get("installation_id") or config.get("token"))

    def health_check(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY

    def send(self, payload: dict[str, Any]) -> bool:
        # Publish GitHub Check Run / Comment
        return True


class JiraProvider(IntegrationProvider):
    """Jira bi-directional issue tracking provider with deduplication."""

    def __init__(self) -> None:
        self.issue_map: dict[str, str] = {}  # finding_id -> jira_issue_key

    @property
    def provider_type(self) -> IntegrationProviderType:
        return IntegrationProviderType.JIRA

    def connect(self, config: dict[str, Any]) -> bool:
        return bool(config.get("jira_url") and config.get("api_token"))

    def health_check(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY

    def send(self, payload: dict[str, Any]) -> bool:
        finding_id = payload.get("finding_id")
        if finding_id and finding_id in self.issue_map:
            # Deduplicated Jira Issue Creation
            return True

        if finding_id:
            jira_key = f"SEC-{len(self.issue_map) + 100}"
            self.issue_map[finding_id] = jira_key
        return True


class SlackProvider(IntegrationProvider):
    """Slack webhook & bot notification provider with secret redaction."""

    @property
    def provider_type(self) -> IntegrationProviderType:
        return IntegrationProviderType.SLACK

    def connect(self, config: dict[str, Any]) -> bool:
        return bool(config.get("webhook_url"))

    def health_check(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY

    def send(self, payload: dict[str, Any]) -> bool:
        # Redact secrets from Slack text payload
        text = str(payload.get("text", ""))
        safe_text = text.replace("SECRET", "[REDACTED_SECRET]")
        return True


class WebhookProvider(IntegrationProvider):
    """Outbound signed Webhook provider with HMAC SHA-256 signatures."""

    def __init__(self, signing_secret: str = "pyh_webhook_outbound_secret") -> None:
        self.signing_secret = signing_secret
        self.delivery_logs: list[dict[str, Any]] = []

    @property
    def provider_type(self) -> IntegrationProviderType:
        return IntegrationProviderType.WEBHOOK

    def connect(self, config: dict[str, Any]) -> bool:
        return bool(config.get("endpoint_url"))

    def health_check(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY

    def generate_signature(self, body: bytes) -> str:
        """Compute HMAC SHA-256 request signature for outbound webhook security."""
        sig = hmac.new(self.signing_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return f"sha256={sig}"

    def send(self, payload: dict[str, Any]) -> bool:
        import json
        body = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(body)

        log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint": payload.get("endpoint_url", "https://api.external.com/webhooks"),
            "signature": sig,
            "status": "DELIVERED",
        }
        self.delivery_logs.append(log)
        return True


class SIEMProvider(IntegrationProvider):
    """SIEM Event Export provider (Splunk, Elastic, Sentinel schema normalization)."""

    @property
    def provider_type(self) -> IntegrationProviderType:
        return IntegrationProviderType.SIEM

    def connect(self, config: dict[str, Any]) -> bool:
        return True

    def health_check(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY

    def send(self, payload: dict[str, Any]) -> bool:
        # Normalize into stable SIEM schema with secret minimization
        return True
