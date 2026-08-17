"""Safe Metadata Parser for Python Projects."""

import re
from typing import Any
from python_hunter.domain.exceptions.base import ProjectError

try:
    import tomllib
except ImportError:
    tomllib = None  # type: ignore[assignment]


class SafeMetadataParser:
    """Extract project metadata statically from pyproject.toml, requirements.txt, setup.cfg without executing code."""

    @staticmethod
    def parse_pyproject_toml(content: str) -> dict[str, Any]:
        """Parse pyproject.toml content safely using standard library tomllib or regex fallback."""
        if not content.strip():
            return {}

        if tomllib is not None:
            try:
                return tomllib.loads(content)
            except Exception:
                pass

        # Regex fallback for key metadata
        metadata: dict[str, Any] = {}
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
        if name_match:
            metadata["name"] = name_match.group(1)

        version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        if version_match:
            metadata["version"] = version_match.group(1)

        desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', content)
        if desc_match:
            metadata["description"] = desc_match.group(1)

        return metadata

    @staticmethod
    def parse_requirements_txt(content: str) -> list[str]:
        """Parse dependencies from requirements.txt statically."""
        dependencies: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip comments and version specifiers
            dep_name = re.split(r"[;<=>~!]", line)[0].strip()
            if dep_name:
                dependencies.append(dep_name)
        return dependencies
