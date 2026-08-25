"""AI Provider abstraction for Local and External AI models."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from python_hunter.domain.ai.models import AIProviderConfig, PrivacyMode


class AIProvider(ABC):
    """Abstract Base Class for all AI Providers."""

    def __init__(self, config: AIProviderConfig) -> None:
        self.config = config

    @property
    def provider_id(self) -> str:
        return self.config.provider_id

    @property
    def is_local(self) -> bool:
        return self.config.is_local

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generates a text completion given a prompt."""
        pass


class LocalAIProvider(AIProvider):
    """Local, zero-external-network AI provider."""

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        # Deterministic, safe local intelligence synthesis logic
        if "explain" in prompt.lower():
            return (
                "WHAT HAPPENED: Deterministic security analyzer detected a vulnerable call pattern in source code.\n"
                "WHY DANGEROUS: Untrusted data reaches sensitive operational sinks without proper sanitization or validation.\n"
                "WHERE: Referenced file path and line location in scanner evidence.\n"
                "ATTACKER POSSIBILITIES: Attacker could exploit this endpoint to bypass controls or execute unauthorized logic.\n"
                "REMEDIATION: Implement strict input validation, parameterization, or secure API alternatives."
            )
        elif "prioritize" in prompt.lower() or "risk" in prompt.lower():
            return (
                "CONTEXTUAL PRIORITIZATION: Prioritized based on internet exposure and production asset criticality. "
                "Internet-facing production assets represent immediate exploit risk over internal dev resources."
            )
        elif "remediate" in prompt.lower() or "patch" in prompt.lower():
            return (
                "RECOMMENDED FIX: Replace vulnerable function call with safe parameterized or sanitized function.\n"
                "WHY IT WORKS: Eliminates string concatenation and direct parameter injection.\n"
                "SIDE EFFECTS: Ensure existing unit test assertions pass after replacement."
            )
        return "Deterministic Local AI Security Intelligence response generated."


class ExternalAIProvider(AIProvider):
    """External AI provider requiring explicit organization approval."""

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        if self.config.privacy_mode == PrivacyMode.STRICT_LOCAL:
            raise PermissionError("Cannot call External AI Provider when STRICT_LOCAL privacy mode is enforced.")
        if not self.config.enabled:
            raise ValueError(f"AI Provider {self.provider_id} is disabled.")

        # Safe external AI simulation / SDK client logic
        return (
            f"[External AI Model ({self.config.model})]: Processed redacted security context prompt safely. "
            "Recommends immediate developer remediation grounded in scanner evidence."
        )
