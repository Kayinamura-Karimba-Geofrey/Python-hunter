"""setup.py and setup.cfg Static Manifest Parsers (Zero Code Execution)."""

import ast
import configparser
import os
import re
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencySource,
    DependencyType,
    ManifestType,
    PackageManager,
    SourceType,
)
from python_hunter.infrastructure.dependencies.parsers.base import BaseManifestParser


class SetuptoolsParser(BaseManifestParser):
    """Static parser for setup.py (via AST) and setup.cfg without executing any Python code."""

    manifest_type = ManifestType.SETUP_PY
    package_manager = PackageManager.SETUPTOOLS

    def can_parse(self, file_path: str) -> bool:
        basename = os.path.basename(file_path).lower()
        return basename in ("setup.py", "setup.cfg")

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        basename = os.path.basename(file_path).lower()
        if basename == "setup.cfg":
            self.manifest_type = ManifestType.SETUP_CFG
            return self._parse_setup_cfg(file_path, content)
        return self._parse_setup_py_ast(file_path, content)

    def _parse_setup_cfg(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        cfg = configparser.ConfigParser()
        try:
            cfg.read_string(content)
        except Exception:
            return dependencies

        if cfg.has_option("options", "install_requires"):
            req_str = cfg.get("options", "install_requires")
            for line in req_str.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    dep = self._create_dep(line, file_path, is_dev=False)
                    if dep:
                        dependencies.append(dep)

        if cfg.has_section("options.extras_require"):
            for group, req_str in cfg.items("options.extras_require"):
                is_dev = group.lower() in ("dev", "test", "lint")
                for line in req_str.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dep = self._create_dep(line, file_path, is_dev=is_dev, extra=group)
                        if dep:
                            dependencies.append(dep)
        return dependencies

    def _parse_setup_py_ast(self, file_path: str, content: str) -> list[Dependency]:
        """Pure static AST parsing of setup.py looking for setup(install_requires=[...])."""
        dependencies: list[Dependency] = []
        import textwrap
        content = textwrap.dedent(content)
        try:
            tree = ast.parse(content)
        except Exception:
            return dependencies

        def _get_str(node: ast.AST) -> str | None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if hasattr(node, "s") and isinstance(getattr(node, "s"), str):
                return getattr(node, "s")
            return None

        class SetupVisitor(ast.NodeVisitor):
            def __init__(visitor_self) -> None:
                visitor_self.install_requires: list[str] = []
                visitor_self.extras_require: dict[str, list[str]] = {}

            def visit_Call(visitor_self, node: ast.Call) -> None:
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name == "setup":
                    for kw in node.keywords:
                        if kw.arg == "install_requires" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            for elt in kw.value.elts:
                                val = _get_str(elt)
                                if val:
                                    visitor_self.install_requires.append(val)
                        elif kw.arg == "extras_require" and isinstance(kw.value, ast.Dict):
                            for k, v in zip(kw.value.keys, kw.value.values):
                                k_val = _get_str(k)
                                if k_val and isinstance(v, (ast.List, ast.Tuple)):
                                    group_reqs = []
                                    for elt in v.elts:
                                        elt_val = _get_str(elt)
                                        if elt_val:
                                            group_reqs.append(elt_val)
                                    visitor_self.extras_require[k_val] = group_reqs
                visitor_self.generic_visit(node)

        visitor = SetupVisitor()
        visitor.visit(tree)

        for req in visitor.install_requires:
            dep = self._create_dep(req, file_path, is_dev=False)
            if dep:
                dependencies.append(dep)

        for group_name, req_list in visitor.extras_require.items():
            is_dev = group_name.lower() in ("dev", "test", "lint")
            for req in req_list:
                dep = self._create_dep(req, file_path, is_dev=is_dev, extra=group_name)
                if dep:
                    dependencies.append(dep)

        return dependencies

    def _create_dep(self, req_str: str, file_path: str, is_dev: bool, extra: str = "") -> Dependency | None:
        line = req_str.strip()
        if not line or line.startswith("#"):
            return None

        marker = ""
        if ";" in line:
            parts = line.split(";", 1)
            line = parts[0].strip()
            marker = parts[1].strip()

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
