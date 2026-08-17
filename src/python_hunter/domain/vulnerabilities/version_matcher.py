"""Version Range Evaluator for Vulnerability Intelligence."""

import logging
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from python_hunter.domain.dependencies.models import Dependency
from python_hunter.domain.vulnerabilities.models import (
    AffectedRange,
    Vulnerability,
    VulnerabilityMatch,
    VulnerabilityStatus,
)

logger = logging.getLogger(__name__)


class VersionMatcher:
    """Evaluates dependencies against vulnerability affected ranges."""

    @classmethod
    def evaluate(
        self,
        vulnerability: Vulnerability,
        dependency: Dependency,
        dependency_paths: list[list[str]] | None = None,
    ) -> VulnerabilityMatch:
        """Evaluate a dependency against a vulnerability record."""
        paths = dependency_paths or []

        # 1. Check if vulnerability is withdrawn
        if vulnerability.is_withdrawn:
            return VulnerabilityMatch(
                vulnerability=vulnerability,
                dependency=dependency,
                status=VulnerabilityStatus.WITHDRAWN,
                dependency_paths=paths,
                explanation="Vulnerability advisory has been withdrawn by source.",
            )

        installed_ver = dependency.version.strip()
        constraint_str = dependency.version_constraint.strip()

        # 2. Handle missing exact version & constraint
        if not installed_ver and not constraint_str:
            return VulnerabilityMatch(
                vulnerability=vulnerability,
                dependency=dependency,
                status=VulnerabilityStatus.UNKNOWN,
                dependency_paths=paths,
                explanation="Exact package version is unknown.",
            )

        # 3. Evaluate exact resolved version if present
        if installed_ver:
            try:
                parsed_ver = Version(installed_ver)
                is_affected = self._is_version_affected(parsed_ver, vulnerability.affected_ranges)
                status = VulnerabilityStatus.AFFECTED if is_affected else VulnerabilityStatus.NOT_AFFECTED
                
                fix, compatible = self._calculate_remediation(parsed_ver, constraint_str, vulnerability.fixed_versions)

                return VulnerabilityMatch(
                    vulnerability=vulnerability,
                    dependency=dependency,
                    status=status,
                    dependency_paths=paths,
                    recommended_fix=fix,
                    constraint_compatible=compatible,
                    explanation=f"Installed version {installed_ver} is {'vulnerable' if is_affected else 'safe'}.",
                )
            except InvalidVersion:
                logger.debug(f"Invalid packaging version: {installed_ver}")
                # Fallback to specifier range check below

        # 4. Evaluate declared version constraint range if no exact version or version parsing failed
        if constraint_str:
            overlaps = self._constraint_overlaps_affected(constraint_str, vulnerability.affected_ranges)
            status = VulnerabilityStatus.POTENTIALLY_AFFECTED if overlaps else VulnerabilityStatus.NOT_AFFECTED

            return VulnerabilityMatch(
                vulnerability=vulnerability,
                dependency=dependency,
                status=status,
                dependency_paths=paths,
                recommended_fix=vulnerability.fixed_versions[0] if vulnerability.fixed_versions else None,
                constraint_compatible=True,
                explanation=f"Declared constraint '{constraint_str}' {'overlaps with' if overlaps else 'does not overlap'} affected version ranges.",
            )

        return VulnerabilityMatch(
            vulnerability=vulnerability,
            dependency=dependency,
            status=VulnerabilityStatus.UNKNOWN,
            dependency_paths=paths,
            explanation="Could not evaluate version status.",
        )

    @classmethod
    def _is_version_affected(cls, ver: Version, affected_ranges: list[AffectedRange]) -> bool:
        """Check if a specific Version object falls within any affected range."""
        if not affected_ranges:
            return False

        for range_obj in affected_ranges:
            intervals = cls._build_intervals(range_obj.events)
            for introduced_ver, fixed_ver in intervals:
                in_range = True
                if introduced_ver:
                    in_range = in_range and (ver >= introduced_ver)
                if fixed_ver:
                    in_range = in_range and (ver < fixed_ver)
                if in_range:
                    return True
        return False

    @classmethod
    def _constraint_overlaps_affected(cls, constraint_str: str, affected_ranges: list[AffectedRange]) -> bool:
        """Check if a VersionSpecifier constraint range overlaps with affected intervals."""
        try:
            spec = SpecifierSet(constraint_str)
        except Exception:
            return True  # Permissive fallback for invalid constraints

        if not affected_ranges:
            return False

        for range_obj in affected_ranges:
            intervals = cls._build_intervals(range_obj.events)
            for introduced_ver, fixed_ver in intervals:
                # Test candidate versions at edges and sample points
                test_points = []
                if introduced_ver:
                    test_points.append(introduced_ver)
                if fixed_ver:
                    test_points.append(fixed_ver)
                
                # If constraint accepts any introduced/affected test points, there is an overlap
                for point in test_points:
                    if point in spec:
                        return True
        return False

    @classmethod
    def _build_intervals(cls, events: list[dict[str, str]]) -> list[tuple[Version | None, Version | None]]:
        """Convert OSV events sequence into [(introduced, fixed), ...] Version intervals."""
        intervals: list[tuple[Version | None, Version | None]] = []
        current_introduced: Version | None = None

        for event in events:
            if "introduced" in event:
                raw_intro = event["introduced"].strip()
                if raw_intro == "0":
                    current_introduced = Version("0.0.0")
                else:
                    try:
                        current_introduced = Version(raw_intro)
                    except InvalidVersion:
                        current_introduced = None
            elif "fixed" in event:
                raw_fixed = event["fixed"].strip()
                try:
                    fixed_ver = Version(raw_fixed)
                except InvalidVersion:
                    fixed_ver = None
                intervals.append((current_introduced, fixed_ver))
                current_introduced = None
            elif "last_affected" in event:
                # Treat last_affected as upper limit
                current_introduced = None

        if current_introduced is not None:
            intervals.append((current_introduced, None))

        return intervals

    @classmethod
    def _calculate_remediation(
        cls, installed_ver: Version, constraint_str: str, fixed_versions: list[str]
    ) -> tuple[str | None, bool]:
        """Find the minimal safe fixed version and check compatibility with project constraint."""
        if not fixed_versions:
            return None, True

        parsed_fixes: list[tuple[Version, str]] = []
        for fix in fixed_versions:
            try:
                parsed_fixes.append((Version(fix), fix))
            except InvalidVersion:
                continue

        parsed_fixes.sort(key=lambda x: x[0])
        # Find smallest fixed version greater than installed version
        recommended_fix = None
        for fix_ver, fix_str in parsed_fixes:
            if fix_ver > installed_ver:
                recommended_fix = fix_str
                break

        if not recommended_fix and parsed_fixes:
            recommended_fix = parsed_fixes[-1][1]

        # Check constraint compatibility if project constraint exists
        compatible = True
        if recommended_fix and constraint_str:
            try:
                spec = SpecifierSet(constraint_str)
                compatible = Version(recommended_fix) in spec
            except Exception:
                compatible = True

        return recommended_fix, compatible
