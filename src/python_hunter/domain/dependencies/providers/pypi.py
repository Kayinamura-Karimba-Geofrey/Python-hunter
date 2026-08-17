"""PyPI Package Metadata Provider (HTTPS, offline-first fallback)."""

import json
import urllib.request
from python_hunter.domain.dependencies.providers.base import (
    PackageMetadata,
    PackageMetadataProvider,
)


class PyPIMetadataProvider(PackageMetadataProvider):
    """Fetches public package metadata from PyPI JSON API with timeout and offline fallback."""

    def __init__(self, timeout_seconds: float = 3.0, enable_network: bool = False) -> None:
        self.timeout_seconds = timeout_seconds
        self.enable_network = enable_network

    def get_metadata(self, package_name: str) -> PackageMetadata | None:
        if not self.enable_network:
            return None

        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PythonHunter/0.1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    return None
                data = json.loads(response.read().decode("utf-8"))

            info = data.get("info", {})
            releases = data.get("releases", {})

            latest = info.get("version", "")
            history = list(releases.keys())
            yanked_dict = {}

            for ver, rel_list in releases.items():
                for item in rel_list:
                    if item.get("yanked"):
                        yanked_dict[ver] = item.get("yanked_reason", "Yanked release")

            return PackageMetadata(
                name=info.get("name", package_name),
                latest_version=latest,
                release_history=history,
                yanked_versions=yanked_dict,
                homepage=info.get("home_page", ""),
                repository_url=info.get("project_url", ""),
                license=info.get("license", ""),
                summary=info.get("summary", ""),
                author=info.get("author", ""),
            )
        except Exception:
            return None
