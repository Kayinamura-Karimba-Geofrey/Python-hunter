"""Cached Package Metadata Provider Wrapper."""

from python_hunter.domain.dependencies.providers.base import (
    PackageMetadata,
    PackageMetadataProvider,
)


class CachedMetadataProvider(PackageMetadataProvider):
    """Caching wrapper decorator around another metadata provider."""

    def __init__(self, provider: PackageMetadataProvider) -> None:
        self.provider = provider
        self._cache: dict[str, PackageMetadata | None] = {}

    def get_metadata(self, package_name: str) -> PackageMetadata | None:
        key = package_name.lower()
        if key in self._cache:
            return self._cache[key]

        meta = self.provider.get_metadata(package_name)
        self._cache[key] = meta
        return meta
