"""Version Abstraction and Constraint Specifier Engine."""

from typing import Any
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class VersionSpec:
    """Encapsulates version comparison, specifier parsing, and conflict detection."""

    @staticmethod
    def parse_version(version_str: str) -> Version | None:
        """Parse raw version string into packaging Version object."""
        if not version_str:
            return None
        cleaned = version_str.strip().lstrip("v")
        try:
            return Version(cleaned)
        except InvalidVersion:
            return None

    @staticmethod
    def parse_specifier(spec_str: str) -> SpecifierSet | None:
        """Parse raw version constraint string into packaging SpecifierSet."""
        if not spec_str:
            return SpecifierSet("")
        try:
            return SpecifierSet(spec_str)
        except InvalidSpecifier:
            return None

    @classmethod
    def matches(cls, version_str: str, constraint_str: str) -> bool:
        """Check if version satisfies given constraint specifier."""
        ver = cls.parse_version(version_str)
        spec = cls.parse_specifier(constraint_str)
        if ver is None or spec is None:
            return False
        return ver in spec

    @classmethod
    def are_conflicting(cls, constraint_a: str, constraint_b: str) -> bool:
        """Detect if two version specifiers are mutually exclusive / conflicting."""
        spec_a = cls.parse_specifier(constraint_a)
        spec_b = cls.parse_specifier(constraint_b)
        if spec_a is None or spec_b is None:
            return False

        # Attempt sampling candidate versions
        test_versions = ["0.0.1", "1.0.0", "2.0.0", "2.19.0", "2.31.0", "3.0.0", "5.0.0"]
        for spec_item in list(spec_a) + list(spec_b):
            test_versions.append(spec_item.version)

        valid_sample_exists = False
        for v_str in test_versions:
            ver = cls.parse_version(v_str)
            if ver and ver in spec_a and ver in spec_b:
                valid_sample_exists = True
                break

        return not valid_sample_exists

    @classmethod
    def is_broad_range(cls, constraint_str: str) -> bool:
        """Detect if version specifier allows excessively broad major version ranges (e.g. >=1)."""
        if not constraint_str:
            return True
        spec = cls.parse_specifier(constraint_str)
        if not spec:
            return False
        for req in spec:
            if req.operator in (">=", ">") and (req.version in ("1", "2", "0") or req.version.endswith(".0")):
                return True
        return False
