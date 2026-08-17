"""pyproject.toml Manifest Parser."""

import os
import tomllib
from typing import Any
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencySource,
    DependencyType,
    ManifestType,
    PackageManager,
    SourceType,
)
from python_hunter.infrastructure.dependencies.parsers.base import BaseManifestParser


class PyProjectParser(BaseManifestParser):
    """Parser for pyproject.toml adhering to PEP 621, Poetry, Flit, and Hatch standards."""

    manifest_type = ManifestType.PYPROJECT_TOML
    package_manager = PackageManager.POETRY  # Default fallback, refined during parsing

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == "pyproject.toml"

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        try:
            data = tomllib.loads(content)
        except Exception:
            return dependencies

        # 1. Standard PEP 621 [project.dependencies]
        project = data.get("project", {})
        if isinstance(project, dict):
            reqs = project.get("dependencies", [])
            if isinstance(reqs, list):
                for req in reqs:
                    dep = self._parse_pep621_req(req, file_path, is_dev=False)
                    if dep:
                        dependencies.append(dep)

            # PEP 621 [project.optional-dependencies]
            opt_reqs = project.get("optional-dependencies", {})
            if isinstance(opt_reqs, dict):
                for group_name, group_list in opt_reqs.items():
                    is_dev = group_name.lower() in ("dev", "test", "lint", "typing")
                    if isinstance(group_list, list):
                        for req in group_list:
                            dep = self._parse_pep621_req(req, file_path, is_dev=is_dev, extra=group_name)
                            if dep:
                                dep.is_optional = True
                                dependencies.append(dep)

        # 2. Tool Poetry [tool.poetry]
        tool = data.get("tool", {})
        if isinstance(tool, dict) and "poetry" in tool:
            self.package_manager = PackageManager.POETRY
            poetry = tool["poetry"]
            if isinstance(poetry, dict):
                # Main dependencies
                poetry_deps = poetry.get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for name, spec in poetry_deps.items():
                        if name.lower() == "python":
                            continue
                        dep = self._parse_poetry_spec(name, spec, file_path, is_dev=False)
                        if dep:
                            dependencies.append(dep)

                # Dev dependencies
                dev_deps = poetry.get("dev-dependencies", {})
                if isinstance(dev_deps, dict):
                    for name, spec in dev_deps.items():
                        dep = self._parse_poetry_spec(name, spec, file_path, is_dev=True)
                        if dep:
                            dependencies.append(dep)

                # Groups [tool.poetry.group.*.dependencies]
                groups = poetry.get("group", {})
                if isinstance(groups, dict):
                    for group_name, group_data in groups.items():
                        is_dev = group_name.lower() in ("dev", "test", "lint")
                        if isinstance(group_data, dict):
                            g_deps = group_data.get("dependencies", {})
                            if isinstance(g_deps, dict):
                                for name, spec in g_deps.items():
                                    dep = self._parse_poetry_spec(name, spec, file_path, is_dev=is_dev, extra=group_name)
                                    if dep:
                                        dependencies.append(dep)

        return dependencies

    def _parse_pep621_req(
        self, req_str: str, file_path: str, is_dev: bool = False, extra: str = ""
    ) -> Dependency | None:
        if not isinstance(req_str, str) or not req_str.strip():
            return None

        # Split specifiers and markers
        marker = ""
        line = req_str.strip()
        if ";" in line:
            parts = line.split(";", 1)
            line = parts[0].strip()
            marker = parts[1].strip()

        # Extract name and constraint
        import re
        match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[(.*?)\])?\s*(.*)$", line)
        if not match:
            return None

        pkg_name = match.group(1)
        req_extra = match.group(2) or extra
        constraint = match.group(3).strip()

        exact_ver = ""
        if constraint.startswith("=="):
            exact_ver = constraint.lstrip("=").strip().split(",")[0]

        types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
        return Dependency(
            name=pkg_name,
            version=exact_ver,
            version_constraint=constraint,
            dependency_types=types,
            source=DependencySource(source_type=SourceType.PYPI),
            manifest_path=file_path,
            is_direct=True,
            is_development=is_dev,
            platform_marker=marker,
            extra=req_extra,
        )

    def _parse_poetry_spec(
        self, name: str, spec: Any, file_path: str, is_dev: bool = False, extra: str = ""
    ) -> Dependency | None:
        constraint = ""
        exact_ver = ""
        source_type = SourceType.PYPI
        url = ""
        git_repo = ""
        git_ref = ""

        if isinstance(spec, str):
            constraint = spec
            if spec.startswith("=="):
                exact_ver = spec.lstrip("=")
        elif isinstance(spec, dict):
            if "version" in spec:
                constraint = str(spec["version"])
            if "git" in spec:
                source_type = SourceType.VCS
                git_repo = str(spec["git"])
                git_ref = str(spec.get("rev", spec.get("branch", spec.get("tag", ""))))
            elif "url" in spec:
                source_type = SourceType.URL
                url = str(spec["url"])

        source = DependencySource(
            source_type=source_type,
            url=url,
            vcs_repo=git_repo,
            vcs_ref=git_ref,
        )
        types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
        return Dependency(
            name=name,
            version=exact_ver,
            version_constraint=constraint,
            dependency_types=types,
            source=source,
            manifest_path=file_path,
            is_direct=True,
            is_development=is_dev,
            extra=extra,
        )
