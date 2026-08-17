"""Deterministic Fake Vulnerability Provider for Unit and Security Tests."""

from python_hunter.domain.vulnerabilities.models import PackageIdentity, Vulnerability
from python_hunter.domain.vulnerabilities.providers.base import (
    ProviderStatus,
    VulnerabilityProvider,
)


class FakeVulnerabilityProvider(VulnerabilityProvider):
    """Fake vulnerability provider loaded with pre-configured synthetic vulnerability records."""

    def __init__(self, records: dict[str, list[Vulnerability]] | None = None) -> None:
        self.records: dict[str, list[Vulnerability]] = records or {}
        self._status = ProviderStatus.AVAILABLE

    @property
    def name(self) -> str:
        return "FakeProvider"

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def set_status(self, new_status: ProviderStatus) -> None:
        self._status = new_status

    def add_vulnerability(self, package_name: str, vulnerability: Vulnerability) -> None:
        norm_name = package_name.strip().lower().replace("_", "-")
        if norm_name not in self.records:
            self.records[norm_name] = []
        self.records[norm_name].append(vulnerability)

    def query(self, package: PackageIdentity, version: str | None = None) -> list[Vulnerability]:
        if self._status in (ProviderStatus.UNAVAILABLE, ProviderStatus.ERROR):
            return []
        return self.records.get(package.normalized_name, [])
