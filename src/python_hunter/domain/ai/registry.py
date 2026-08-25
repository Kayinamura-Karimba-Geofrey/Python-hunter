"""Registry for dynamic registration and configuration of AI Providers."""

from typing import Dict, List, Optional
from python_hunter.domain.ai.models import AIProviderConfig, PrivacyMode
from python_hunter.domain.ai.provider import AIProvider, LocalAIProvider, ExternalAIProvider


class AIProviderRegistry:
    """Registry to register, configure, enable, and retrieve AI Providers."""

    def __init__(self) -> None:
        self._providers: Dict[str, AIProvider] = {}
        # Register default local provider
        default_cfg = AIProviderConfig(
            provider_id="local_default",
            name="Default Local AI",
            enabled=True,
            is_local=True,
            model="local-security-v1",
            privacy_mode=PrivacyMode.STRICT_LOCAL
        )
        self.register(LocalAIProvider(default_cfg))

    def register(self, provider: AIProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> Optional[AIProvider]:
        return self._providers.get(provider_id)

    def list_providers(self) -> List[AIProviderConfig]:
        return [p.config for p in self._providers.values()]

    def set_enabled(self, provider_id: str, enabled: bool) -> bool:
        provider = self.get(provider_id)
        if provider:
            provider.config.enabled = enabled
            return True
        return False

    def get_active_provider(self, requested_id: Optional[str] = None) -> AIProvider:
        if requested_id and requested_id in self._providers:
            p = self._providers[requested_id]
            if p.config.enabled:
                return p
        # Fallback to local default
        default_p = self.get("local_default")
        if default_p and default_p.config.enabled:
            return default_p
        raise RuntimeError("No active or enabled AI Provider available.")
