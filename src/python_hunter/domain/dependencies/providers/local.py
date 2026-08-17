"""Offline Local Package Metadata Provider."""

from python_hunter.domain.dependencies.providers.base import (
    PackageMetadata,
    PackageMetadataProvider,
)


class LocalMetadataProvider(PackageMetadataProvider):
    """Offline provider returning empty/local metadata without network requests."""

    def __init__(self, known_metadata: dict[str, PackageMetadata] | None = None) -> None:
        self.known_metadata = known_metadata or {}

    def get_metadata(self, package_name: str) -> PackageMetadata | None:
        return self.known_metadata.get(package_name.lower())
