"""Pull Request Dependency Diff & Regression Detection Engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set
from python_hunter.domain.dependencies.models import Dependency
from python_hunter.domain.dependencies.semver_engine import SemVerEngine
from python_hunter.domain.dependencies.vulnerability_intel import Advisory, VulnerabilityIntelligence


class DependencyChangeType(str, Enum):
    VULNERABILITY_INTRODUCED = "VULNERABILITY_INTRODUCED"
    VULNERABILITY_FIXED = "VULNERABILITY_FIXED"
    DEPENDENCY_ADDED = "DEPENDENCY_ADDED"
    DEPENDENCY_REMOVED = "DEPENDENCY_REMOVED"
    DEPENDENCY_UPGRADED = "DEPENDENCY_UPGRADED"
    DEPENDENCY_DOWNGRADED = "DEPENDENCY_DOWNGRADED"
    TRANSITIVE_REGRESSION = "TRANSITIVE_REGRESSION"
    LOCKFILE_REGRESSION = "LOCKFILE_REGRESSION"


@dataclass
class DependencyDiffItem:
    package_name: str
    base_version: str
    head_version: str
    change_type: DependencyChangeType
    is_transitive: bool
    advisories: List[Advisory] = field(default_factory=list)
    description: str = ""


@dataclass
class PRDependencyDiffResult:
    has_regressions: bool
    total_added: int = 0
    total_removed: int = 0
    total_upgraded: int = 0
    total_downgraded: int = 0
    introduced_vulnerabilities: int = 0
    fixed_vulnerabilities: int = 0
    diff_items: List[DependencyDiffItem] = field(default_factory=list)


class PRDependencyDiffEngine:
    """Compares BASE vs HEAD dependency state for PR checks and regression prevention."""

    def __init__(self, intel: VulnerabilityIntelligence) -> None:
        self.intel = intel

    def compare_dependencies(
        self,
        base_deps: List[Dependency],
        head_deps: List[Dependency],
    ) -> PRDependencyDiffResult:
        base_map: Dict[str, Dependency] = {d.normalized_name: d for d in base_deps}
        head_map: Dict[str, Dependency] = {d.normalized_name: d for d in head_deps}

        diff_items: List[DependencyDiffItem] = []
        introduced_vulns = 0
        fixed_vulns = 0
        added = 0
        removed = 0
        upgraded = 0
        downgraded = 0

        # Check HEAD vs BASE
        for norm_name, head_dep in head_map.items():
            head_ver = head_dep.version or "0.0.0"
            head_advs = self.intel.match_advisories(head_dep.name, head_ver, head_dep.ecosystem)

            if norm_name not in base_map:
                added += 1
                change_type = DependencyChangeType.DEPENDENCY_ADDED
                if head_advs:
                    introduced_vulns += 1
                    change_type = DependencyChangeType.VULNERABILITY_INTRODUCED

                diff_items.append(DependencyDiffItem(
                    package_name=head_dep.name,
                    base_version="",
                    head_version=head_ver,
                    change_type=change_type,
                    is_transitive=head_dep.is_transitive,
                    advisories=head_advs,
                    description=f"New dependency '{head_dep.name}' ({head_ver}) introduced in PR.",
                ))
            else:
                base_dep = base_map[norm_name]
                base_ver = base_dep.version or "0.0.0"
                base_advs = self.intel.match_advisories(base_dep.name, base_ver, base_dep.ecosystem)

                cmp = SemVerEngine.compare_versions(head_ver, base_ver)
                if cmp > 0:
                    upgraded += 1
                    change_type = DependencyChangeType.DEPENDENCY_UPGRADED
                    if head_advs and not base_advs:
                        introduced_vulns += 1
                        change_type = DependencyChangeType.VULNERABILITY_INTRODUCED
                    elif base_advs and not head_advs:
                        fixed_vulns += 1
                        change_type = DependencyChangeType.VULNERABILITY_FIXED

                    diff_items.append(DependencyDiffItem(
                        package_name=head_dep.name,
                        base_version=base_ver,
                        head_version=head_ver,
                        change_type=change_type,
                        is_transitive=head_dep.is_transitive,
                        advisories=head_advs,
                        description=f"Upgraded '{head_dep.name}' from {base_ver} to {head_ver}.",
                    ))
                elif cmp < 0:
                    downgraded += 1
                    change_type = DependencyChangeType.DEPENDENCY_DOWNGRADED
                    if head_advs and not base_advs:
                        introduced_vulns += 1
                        change_type = DependencyChangeType.VULNERABILITY_INTRODUCED

                    diff_items.append(DependencyDiffItem(
                        package_name=head_dep.name,
                        base_version=base_ver,
                        head_version=head_ver,
                        change_type=change_type,
                        is_transitive=head_dep.is_transitive,
                        advisories=head_advs,
                        description=f"Downgraded '{head_dep.name}' from {base_ver} to {head_ver} (Potential Regression).",
                    ))

        # Check REMOVED
        for norm_name, base_dep in base_map.items():
            if norm_name not in head_map:
                removed += 1
                base_ver = base_dep.version or "0.0.0"
                base_advs = self.intel.match_advisories(base_dep.name, base_ver, base_dep.ecosystem)
                if base_advs:
                    fixed_vulns += 1

                diff_items.append(DependencyDiffItem(
                    package_name=base_dep.name,
                    base_version=base_ver,
                    head_version="",
                    change_type=DependencyChangeType.DEPENDENCY_REMOVED,
                    is_transitive=base_dep.is_transitive,
                    description=f"Removed dependency '{base_dep.name}' ({base_ver}).",
                ))

        has_regressions = introduced_vulns > 0 or downgraded > 0

        return PRDependencyDiffResult(
            has_regressions=has_regressions,
            total_added=added,
            total_removed=removed,
            total_upgraded=upgraded,
            total_downgraded=downgraded,
            introduced_vulnerabilities=introduced_vulns,
            fixed_vulnerabilities=fixed_vulns,
            diff_items=diff_items,
        )
