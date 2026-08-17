"""Dependency Domain Entities, Value Objects, and Graph Representations."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.dependencies.normalization import normalize_package_name


class Ecosystem(str, Enum):
    """Supported dependency ecosystems."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GENERIC = "generic"


class DependencyType(str, Enum):
    """Taxonomy of dependency lifecycle and usage types."""

    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"
    DEVELOPMENT = "DEVELOPMENT"
    OPTIONAL = "OPTIONAL"
    TEST = "TEST"
    BUILD = "BUILD"
    RUNTIME = "RUNTIME"
    UNKNOWN = "UNKNOWN"


class PackageManager(str, Enum):
    """Supported Python packaging tools."""

    PIP = "pip"
    POETRY = "poetry"
    PIPENV = "pipenv"
    UV = "uv"
    SETUPTOOLS = "setuptools"
    UNKNOWN = "unknown"


class ManifestType(str, Enum):
    """Supported dependency manifest file types."""

    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    PIPFILE = "Pipfile"
    PIPFILE_LOCK = "Pipfile.lock"
    POETRY_LOCK = "poetry.lock"
    UV_LOCK = "uv.lock"
    SETUP_PY = "setup.py"
    SETUP_CFG = "setup.cfg"


class SourceType(str, Enum):
    """Source origin of a dependency package."""

    PYPI = "pypi"
    VCS = "vcs"
    URL = "url"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass
class DependencySource:
    """Detailed source origin and integrity hashes of a package."""

    source_type: SourceType = SourceType.PYPI
    url: str = ""
    vcs_repo: str = ""
    vcs_ref: str = ""
    hashes: list[str] = field(default_factory=list)


@dataclass
class Dependency:
    """Normalized domain entity representing a single third-party dependency."""

    name: str
    normalized_name: str = ""
    ecosystem: Ecosystem = Ecosystem.PYTHON
    version: str = ""
    version_constraint: str = ""
    dependency_types: set[DependencyType] = field(default_factory=lambda: {DependencyType.RUNTIME})
    source: DependencySource = field(default_factory=DependencySource)
    manifest_path: str = ""
    is_direct: bool = True
    is_transitive: bool = False
    is_optional: bool = False
    is_development: bool = False
    platform_marker: str = ""
    extra: str = ""
    yanked: bool = False
    yanked_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.normalized_name:
            self.normalized_name = normalize_package_name(self.name)


@dataclass
class DependencyGraphNode:
    """Node representation in dependency graph."""

    dependency: Dependency
    dependencies: list[str] = field(default_factory=list)  # List of normalized names


@dataclass
class DependencyGraph:
    """Directed Acyclic Graph (DAG) representing project dependency trees."""

    nodes: dict[str, DependencyGraphNode] = field(default_factory=dict)
    root_dependencies: list[str] = field(default_factory=list)

    def add_dependency(self, dep: Dependency, child_names: list[str] | None = None) -> None:
        """Add a dependency node and its outgoing edge connections."""
        norm_name = dep.normalized_name
        child_norms = [normalize_package_name(c) for c in (child_names or [])]
        self.nodes[norm_name] = DependencyGraphNode(dependency=dep, dependencies=child_norms)
        if dep.is_direct and norm_name not in self.root_dependencies:
            self.root_dependencies.append(norm_name)

    def get_node(self, name: str) -> DependencyGraphNode | None:
        """Retrieve node by name or normalized name."""
        norm = normalize_package_name(name)
        return self.nodes.get(norm)

    def to_tree_str(self) -> str:
        """Render readable ascii dependency tree."""
        lines: list[str] = []
        visited: set[str] = set()

        def _render_node(norm_name: str, prefix: str = "", is_last: bool = True) -> None:
            node = self.nodes.get(norm_name)
            if not node:
                return

            dep = node.dependency
            ver = dep.version or dep.version_constraint or "unpinned"
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{dep.name}=={ver}")

            if norm_name in visited:
                return
            visited.add(norm_name)

            children = node.dependencies
            child_prefix = prefix + ("    " if is_last else "│   ")
            for idx, child in enumerate(children):
                _render_node(child, child_prefix, idx == len(children) - 1)

        for idx, root in enumerate(self.root_dependencies):
            _render_node(root, "", idx == len(self.root_dependencies) - 1)

        return "\n".join(lines)


@dataclass
class DependencyInventory:
    """Structured inventory summary of scanned dependencies."""

    package_manager: PackageManager = PackageManager.UNKNOWN
    manifests: list[str] = field(default_factory=list)
    total_count: int = 0
    direct_count: int = 0
    transitive_count: int = 0
    development_count: int = 0
    optional_count: int = 0
    vcs_count: int = 0
    url_count: int = 0
    local_count: int = 0
    dependencies: list[Dependency] = field(default_factory=list)
    graph: DependencyGraph = field(default_factory=DependencyGraph)
