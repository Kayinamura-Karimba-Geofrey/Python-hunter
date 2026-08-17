"""poetry.lock Manifest Parser."""

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


class PoetryLockParser(BaseManifestParser):
    """Parser for poetry.lock resolved lockfiles."""

    manifest_type = ManifestType.POETRY_LOCK
    package_manager = PackageManager.POETRY

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == "poetry.lock"

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        try:
            data = tomllib.loads(content)
        except Exception:
            return dependencies

        packages = data.get("package", [])
        if not isinstance(packages, list):
            return dependencies

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            if not name:
                continue

            ver = pkg.get("version", "")
            category = pkg.get("category", "main")
            is_dev = category.lower() in ("dev", "test")

            files_info = pkg.get("files", [])
            hashes = []
            if isinstance(files_info, list):
                for f in files_info:
                    if isinstance(f, dict) and "hash" in f:
                        hashes.append(f["hash"])

            deps_dict = pkg.get("dependencies", {})
            child_deps = list(deps_dict.keys()) if isinstance(deps_dict, dict) else []

            types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
            dep = Dependency(
                name=name,
                version=ver,
                version_constraint=f"=={ver}" if ver else "",
                dependency_types=types,
                source=DependencySource(source_type=SourceType.PYPI, hashes=hashes),
                manifest_path=file_path,
                is_direct=False,  # lockfile dependencies defaulted to resolved
                is_transitive=True,
                is_development=is_dev,
                metadata={"child_dependencies": child_deps},
            )
            dependencies.append(dep)

        return dependencies
