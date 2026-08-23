"""Version Range Engine for ecosystem-specific semantic version matching."""

import re
from typing import Any
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


class VersionRangeEngine:
    """Interprets complex version ranges (<, <=, >, >=, ==, ranges, multiple constraints)

    across different package ecosystems (PyPI, npm, Maven, Go, Cargo, etc.).
    """

    @staticmethod
    def _clean_version(ver: str) -> str:
        """Strip leading 'v' or whitespace from version string."""
        ver = ver.strip()
        if ver.startswith("v") or ver.startswith("V"):
            ver = ver[1:]
        return ver

    def parse_semver(self, ver: str) -> Version | None:
        """Attempt to parse a version string into packaging.version.Version."""
        cleaned = self._clean_version(ver)
        try:
            return Version(cleaned)
        except InvalidVersion:
            # Fallback for version strings with non-standard suffixes (e.g. 1.2.3.RELEASE)
            match = re.search(r"(\d+(\.\d+)+)", cleaned)
            if match:
                try:
                    return Version(match.group(1))
                except InvalidVersion:
                    return None
            return None

    def is_version_affected(
        self,
        current_version: str,
        affected_ranges: list[dict[str, Any]],
        fixed_versions: list[str] | None = None,
    ) -> bool:
        """Check if current_version matches any affected ranges or precedes fixed versions."""
        if not current_version or current_version.lower() in ("unknown", "*"):
            return False

        parsed_current = self.parse_semver(current_version)
        if not parsed_current:
            return False

        # If fixed versions are given, check if current version < fixed version
        if fixed_versions:
            for fix_ver in fixed_versions:
                parsed_fix = self.parse_semver(fix_ver)
                if parsed_fix and parsed_current < parsed_fix:
                    # Current version is below a fixed version
                    return True

        # Check OSV events style ranges: [{"introduced": "0"}, {"fixed": "1.2.3"}]
        for rng in affected_ranges:
            events = rng.get("events", [])
            if events:
                introduced = None
                fixed = None
                last_affected = None

                for evt in events:
                    if "introduced" in evt:
                        introduced = evt["introduced"]
                    if "fixed" in evt:
                        fixed = evt["fixed"]
                    if "last_affected" in evt:
                        last_affected = evt["last_affected"]

                is_after_intro = True
                if introduced and introduced != "0":
                    p_intro = self.parse_semver(introduced)
                    if p_intro and parsed_current < p_intro:
                        is_after_intro = False

                is_before_fixed = True
                if fixed:
                    p_fixed = self.parse_semver(fixed)
                    if p_fixed and parsed_current >= p_fixed:
                        is_before_fixed = False

                if last_affected:
                    p_last = self.parse_semver(last_affected)
                    if p_last and parsed_current > p_last:
                        is_before_fixed = False

                if is_after_intro and is_before_fixed:
                    return True

            # Check specifier string style ranges, e.g. ">= 1.0.0, < 1.2.3"
            expression = rng.get("expression") or rng.get("range")
            if expression:
                try:
                    spec = SpecifierSet(expression)
                    if parsed_current in spec:
                        return True
                except Exception:
                    pass

        return False

    def evaluate_status(
        self,
        current_version: str,
        affected_ranges: list[dict[str, Any]],
        fixed_versions: list[str] | None = None,
    ) -> str:
        """Determine detailed status: AFFECTED, UNAFFECTED, FIXED, or UNKNOWN."""
        if not current_version or current_version.lower() in ("unknown", "*"):
            return "UNKNOWN"

        parsed_current = self.parse_semver(current_version)
        if not parsed_current:
            return "UNKNOWN"

        if fixed_versions:
            for fix_ver in fixed_versions:
                parsed_fix = self.parse_semver(fix_ver)
                if parsed_fix and parsed_current >= parsed_fix:
                    return "FIXED"

        if self.is_version_affected(current_version, affected_ranges, fixed_versions):
            return "AFFECTED"

        return "UNAFFECTED"
