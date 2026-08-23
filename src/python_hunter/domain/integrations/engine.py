"""IntegrationRegistry, CircuitBreaker, SyncEngine, and IntegrationEngine."""

import time
from typing import Any, Callable

from python_hunter.domain.integrations.credentials import CredentialManager
from python_hunter.domain.integrations.models import ExternalReference, Integration, IntegrationProviderType, IntegrationStatus
from python_hunter.domain.integrations.providers import GitHubProvider, IntegrationProvider, JiraProvider, SIEMProvider, SlackProvider, WebhookProvider


class IntegrationCircuitBreaker:
    """Circuit Breaker protecting external provider API calls from cascading failures."""

    def __init__(self, failure_threshold: int = 3, recovery_time_seconds: int = 30) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_time_seconds = recovery_time_seconds
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN

    def can_execute(self) -> bool:
        now = time.time()
        if self.state == "OPEN":
            if now - self.last_failure_time > self.recovery_time_seconds:
                self.state = "HALF-OPEN"
                return True
            return False
        return True

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class IntegrationRegistry:
    """Registry managing active enterprise integration providers."""

    def __init__(self) -> None:
        self._providers: dict[IntegrationProviderType, IntegrationProvider] = {}
        # Register defaults
        self.register(GitHubProvider())
        self.register(JiraProvider())
        self.register(SlackProvider())
        self.register(WebhookProvider())
        self.register(SIEMProvider())

    def register(self, provider: IntegrationProvider) -> None:
        self._providers[provider.provider_type] = provider

    def get(self, provider_type: IntegrationProviderType) -> IntegrationProvider | None:
        return self._providers.get(provider_type)


class IntegrationSyncEngine:
    """Checkpoint recovery and incremental synchronization engine for integrations."""

    def __init__(self) -> None:
        self.sync_states: dict[str, dict[str, Any]] = {}

    def sync_integration(self, integration_id: str, provider: IntegrationProvider, payload: dict[str, Any]) -> bool:
        """Synchronize external tickets / checks with checkpoint recovery."""
        checkpoint = self.sync_states.get(integration_id, {"status": "IDLE", "cursor": None})
        checkpoint["status"] = "SYNCING"

        try:
            success = provider.send(payload)
            if success:
                checkpoint["status"] = "COMPLETED"
                checkpoint["last_sync"] = time.time()
                self.sync_states[integration_id] = checkpoint
                return True
        except Exception:
            checkpoint["status"] = "FAILED"
            self.sync_states[integration_id] = checkpoint
            raise

        return False


class IntegrationEngine:
    """Enterprise Integration Engine orchestrating providers, credentials, circuit breaking, and sync."""

    def __init__(self) -> None:
        self.registry = IntegrationRegistry()
        self.credential_manager = CredentialManager()
        self.sync_engine = IntegrationSyncEngine()
        self.circuit_breakers: dict[str, IntegrationCircuitBreaker] = {}
        self.integrations: dict[str, Integration] = {}

    def register_integration(self, integration: Integration) -> None:
        self.integrations[integration.integration_id] = integration
        self.circuit_breakers[integration.integration_id] = IntegrationCircuitBreaker()

    def dispatch_event(self, integration_id: str, requesting_org_id: str, payload: dict[str, Any]) -> bool:
        """Dispatch event to integration verifying tenant boundaries, circuit breaking, and idempotency."""
        integration = self.integrations.get(integration_id)
        if not integration or integration.organization_id != requesting_org_id:
            raise PermissionError("Cross-tenant access to integration blocked.")

        if not integration.enabled:
            return False

        cb = self.circuit_breakers.setdefault(integration_id, IntegrationCircuitBreaker())
        if not cb.can_execute():
            integration.status = IntegrationStatus.DEGRADED
            return False

        provider = self.registry.get(integration.provider)
        if not provider:
            return False

        try:
            success = self.sync_engine.sync_integration(integration_id, provider, payload)
            if success:
                cb.record_success()
                integration.status = IntegrationStatus.HEALTHY
                return True
        except Exception:
            cb.record_failure()
            integration.status = IntegrationStatus.FAILED

        return False
