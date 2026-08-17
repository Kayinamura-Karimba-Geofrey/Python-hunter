"""uv.lock Manifest Parser."""

import os
import tomllib
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencySource,
    DependencyType,
    ManifestType,
    PackageManager,
    SourceType,
)
from python_hunter.infrastructure.dependencies.parsers.base import BaseManifestParser


class UVLockParser(BaseManifestParser):
    """Parser for uv.lock resolved lockfiles."""

    manifest_type = ManifestType.UV_LOCK
    package_manager = PackageManager.UV

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == "uv.lock"

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        try:
            data = tomllib.loads(content)
        except Exception:
            return dependencies

        package_list = data.get("package", [])
        if not isinstance(package_list, list):
            return dependencies

        for pkg in package_list:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            if not name:
                continue
            ver = pkg.get("version", "")

            dependencies.append(
                Dependency(
                    name=name,
                    version=ver,
                    version_constraint=f"=={ver}" if ver else "",
                    dependency_types={DependencyType.RUNTIME},
                    source=DependencySource(source_type=SourceType.PYPI),
                    manifest_path=file_path,
                    is_direct=False,
                    is_transitive=True,
                )
            )
        return dependencies
