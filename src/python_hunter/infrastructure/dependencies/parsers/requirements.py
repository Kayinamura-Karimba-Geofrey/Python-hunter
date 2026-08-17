"""Requirements.txt Static Manifest Parser."""

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


class RequirementsParser(BaseManifestParser):
    """Parser for requirements.txt, requirements-dev.txt, and variants."""

    manifest_type = ManifestType.REQUIREMENTS_TXT
    package_manager = PackageManager.PIP

    VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
    CREDENTIAL_REGEX = re.compile(r"https?://([^:@\s]+):([^@\s]+)@")

    def can_parse(self, file_path: str) -> bool:
        basename = os.path.basename(file_path).lower()
        return "requirements" in basename or basename.endswith(".req")

    @classmethod
    def sanitize_index_url(cls, line: str) -> str:
        """Redact embedded credentials in private repository or index URLs."""
        return cls.CREDENTIAL_REGEX.sub(r"https://[REDACTED]@", line)

    def parse(self, file_path: str, content: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        is_dev = any(k in os.path.basename(file_path).lower() for k in ("dev", "test", "ci"))

        # Combine line continuations (\)
        cleaned_lines: list[str] = []
        buffer = ""
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if line_str.endswith("\\"):
                buffer += line_str[:-1].strip() + " "
            else:
                buffer += line_str
                cleaned_lines.append(buffer.strip())
                buffer = ""

        for line in cleaned_lines:
            line_str = self.sanitize_index_url(line)

            # Skip options like -r, -i, -f, --extra-index-url
            if line_str.startswith(("-", "--")):
                continue

            # Check hashes
            hashes: list[str] = []
            if "--hash" in line_str:
                parts = line_str.split("--hash")
                line_str = parts[0].strip()
                for p in parts[1:]:
                    h_val = p.strip().lstrip("=").strip().split()[0]
                    hashes.append(h_val)

            # Environment marker separation
            marker = ""
            if ";" in line_str:
                parts = line_str.split(";", 1)
                line_str = parts[0].strip()
                marker = parts[1].strip()

            # 1. VCS Reference
            if any(line_str.startswith(pref) for pref in self.VCS_PREFIXES):
                dep = self._parse_vcs(line_str, file_path, is_dev, hashes, marker)
                if dep:
                    dependencies.append(dep)
                continue

            # 2. Direct URL Reference
            if line_str.startswith(("http://", "https://", "ftp://")):
                dep = self._parse_url(line_str, file_path, is_dev, hashes, marker)
                if dep:
                    dependencies.append(dep)
                continue

            # 3. Standard Package Specifier
            dep = self._parse_standard(line_str, file_path, is_dev, hashes, marker)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_vcs(
        self, line: str, file_path: str, is_dev: bool, hashes: list[str], marker: str
    ) -> Dependency | None:
        egg_match = re.search(r"#egg=([A-Za-z0-9_\-\.]+)", line)
        pkg_name = egg_match.group(1) if egg_match else "unknown-vcs-pkg"

        ref = ""
        if "@" in line:
            ref_part = line.split("@", 1)[1]
            ref = ref_part.split("#")[0]

        source = DependencySource(
            source_type=SourceType.VCS,
            url=line.split("#")[0],
            vcs_repo=line,
            vcs_ref=ref,
            hashes=hashes,
        )
        types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
        return Dependency(
            name=pkg_name,
            version_constraint="",
            dependency_types=types,
            source=source,
            manifest_path=file_path,
            is_direct=True,
            is_development=is_dev,
            platform_marker=marker,
        )

    def _parse_url(
        self, line: str, file_path: str, is_dev: bool, hashes: list[str], marker: str
    ) -> Dependency | None:
        filename = line.split("/")[-1].split("#")[0]
        if "-" in filename:
            pkg_name = filename.split("-")[0]
        elif "." in filename:
            pkg_name = filename.split(".")[0]
        else:
            pkg_name = filename or "unknown-url-pkg"

        source = DependencySource(
            source_type=SourceType.URL,
            url=line,
            hashes=hashes,
        )
        types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
        return Dependency(
            name=pkg_name,
            version_constraint="",
            dependency_types=types,
            source=source,
            manifest_path=file_path,
            is_direct=True,
            is_development=is_dev,
            platform_marker=marker,
        )

    def _parse_standard(
        self, line: str, file_path: str, is_dev: bool, hashes: list[str], marker: str
    ) -> Dependency | None:
        # Match package name and version specifiers
        match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[(.*?)\])?\s*(.*)$", line)
        if not match:
            return None

        pkg_name = match.group(1)
        extra = match.group(2) or ""
        constraint = match.group(3).strip()

        exact_ver = ""
        if constraint.startswith("=="):
            exact_ver = constraint.lstrip("=").strip().split(",")[0]

        source = DependencySource(
            source_type=SourceType.PYPI,
            hashes=hashes,
        )
        types = {DependencyType.DEVELOPMENT if is_dev else DependencyType.RUNTIME}
        return Dependency(
            name=pkg_name,
            version=exact_ver,
            version_constraint=constraint,
            dependency_types=types,
            source=source,
            manifest_path=file_path,
            is_direct=True,
            is_development=is_dev,
            platform_marker=marker,
            extra=extra,
        )
