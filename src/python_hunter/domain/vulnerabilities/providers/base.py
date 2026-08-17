"""Vulnerability Provider Abstract Base Interface."""

from abc import ABC, abstractmethod
from enum import Enum

from python_hunter.domain.vulnerabilities.models import PackageIdentity, Vulnerability


class ProviderStatus(str, Enum):
    """Execution and availability status of a vulnerability intelligence provider."""

    AVAILABLE = "AVAILABLE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    OFFLINE = "OFFLINE"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"


class VulnerabilityProvider(ABC):
    """Abstract interface for vulnerability intelligence databases and APIs."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier name (e.g., 'OSV', 'NVD', 'GHSA')."""
        ...

    @property
    @abstractmethod
    def status(self) -> ProviderStatus:
        """Current operational status of the provider."""
        ...

    @abstractmethod
    def query(self, package: PackageIdentity, version: str | None = None) -> list[Vulnerability]:
        """Query vulnerability records for a specific package identity and optional version.
        
        Must handle errors gracefully and return an empty list rather than throwing uncaught API errors.
        """
        ...

    def batch_query(
        self, queries: list[tuple[PackageIdentity, str | None]]
    ) -> dict[str, list[Vulnerability]]:
        """Batch query vulnerability records for multiple packages.
        
        Returns mapping from package.normalized_name -> list of Vulnerability entities.
        Default implementation delegates sequentially to `query()`.
        """
        results: dict[str, list[Vulnerability]] = {}
        for package, version in queries:
            vulnerabilities = self.query(package, version)
            results[package.normalized_name] = vulnerabilities
        return results
