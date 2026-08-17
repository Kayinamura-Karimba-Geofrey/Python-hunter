"""Pipfile and Pipfile.lock Parser."""

import json
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


class PipfileParser(BaseManifestParser):
    """Parser for Pipfile and Pipfile.lock."""

    manifest_type = ManifestType.PIPFILE
    package_manager = PackageManager.PIPENV

    def can_parse(self, file_path: str) -> bool:
        basename = os.path.basename(file_path)
        return basename in ("Pipfile", "Pipfile.lock")

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        basename = os.path.basename(file_path)
        if basename == "Pipfile.lock":
            self.manifest_type = ManifestType.PIPFILE_LOCK
            return self._parse_lockfile(file_path, content)
        return self._parse_pipfile(file_path, content)

    def _parse_pipfile(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        try:
            data = tomllib.loads(content)
        except Exception:
            return dependencies

        sections = [("packages", False), ("dev-packages", True)]
        for sec_name, is_dev in sections:
            sec_data = data.get(sec_name, {})
            if isinstance(sec_data, dict):
                for name, spec in sec_data.items():
                    constraint = spec if isinstance(spec, str) else str(spec.get("version", "")) if isinstance(spec, dict) else ""
                    types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
                    dependencies.append(
                        Dependency(
                            name=name,
                            version_constraint=constraint,
                            dependency_types=types,
                            source=DependencySource(source_type=SourceType.PYPI),
                            manifest_path=file_path,
                            is_direct=True,
                            is_development=is_dev,
                        )
                    )
        return dependencies

    def _parse_lockfile(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        try:
            data = json.loads(content)
        except Exception:
            return dependencies

        sections = [("default", False), ("develop", True)]
        for sec_name, is_dev in sections:
            sec_data = data.get(sec_name, {})
            if isinstance(sec_data, dict):
                for name, info in sec_data.items():
                    if not isinstance(info, dict):
                        continue
                    ver = info.get("version", "").lstrip("=")
                    hashes = info.get("hashes", [])
                    source = DependencySource(source_type=SourceType.PYPI, hashes=hashes)
                    types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=ver,
                            version_constraint=f"=={ver}" if ver else "",
                            dependency_types=types,
                            source=source,
                            manifest_path=file_path,
                            is_direct=True,
                            is_transitive=False,
                            is_development=is_dev,
                        )
                    )
        return dependencies
