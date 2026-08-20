"""Ecosystem-aware SemVer engine for version matching and conflict detection."""

import re
from typing import Any, Dict, List, Optional, Tuple
from python_hunter.domain.dependencies.models import Ecosystem


class SemVerEngine:
    """Ecosystem-aware SemVer parser and range matching engine."""

    @staticmethod
    def parse_version_tuple(version_str: str) -> Tuple[int, int, int, str]:
        """Parses version string into (major, minor, patch, pre_release)."""
        clean_v = re.sub(r"^[v=~^><]+", "", version_str.strip())
        parts = clean_v.split("-", 1)
        main_part = parts[0]
        pre_release = parts[1] if len(parts) > 1 else ""

        digits = re.findall(r"\d+", main_part)
        major = int(digits[0]) if len(digits) > 0 else 0
        minor = int(digits[1]) if len(digits) > 1 else 0
        patch = int(digits[2]) if len(digits) > 2 else 0

        return (major, minor, patch, pre_release)

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
        t1 = SemVerEngine.parse_version_tuple(v1)
        t2 = SemVerEngine.parse_version_tuple(v2)

        for i in range(3):
            if t1[i] < t2[i]:
                return -1
            elif t1[i] > t2[i]:
                return 1

        # Pre-releases are lower than regular releases
        if t1[3] and not t2[3]:
            return -1
        elif not t1[3] and t2[3]:
            return 1
        elif t1[3] < t2[3]:
            return -1
        elif t1[3] > t2[3]:
            return 1

        return 0

    @classmethod
    def is_version_in_range(cls, version: str, constraint: str, ecosystem: Ecosystem = Ecosystem.PYTHON) -> bool:
        """Determines if installed version falls within constraint range."""
        if not constraint or constraint == "*":
            return True

        if "," in constraint:
            sub_constraints = constraint.split(",")
            return all(cls.is_version_in_range(version, sub.strip(), ecosystem) for sub in sub_constraints)

        clean_c = constraint.strip()

        if clean_c.startswith("^"):
            # Caret requirement ^1.2.3: >=1.2.3 < 2.0.0
            base_v = clean_c[1:]
            t_base = cls.parse_version_tuple(base_v)
            upper_bound = f"{t_base[0] + 1}.0.0"
            return cls.compare_versions(version, base_v) >= 0 and cls.compare_versions(version, upper_bound) < 0

        elif clean_c.startswith("~"):
            # Tilde requirement ~1.2.3: >=1.2.3 < 1.3.0
            base_v = clean_c[1:]
            t_base = cls.parse_version_tuple(base_v)
            upper_bound = f"{t_base[0]}.{t_base[1] + 1}.0"
            return cls.compare_versions(version, base_v) >= 0 and cls.compare_versions(version, upper_bound) < 0

        elif clean_c.startswith(">="):
            return cls.compare_versions(version, clean_c[2:]) >= 0
        elif clean_c.startswith(">"):
            return cls.compare_versions(version, clean_c[1:]) > 0
        elif clean_c.startswith("<="):
            return cls.compare_versions(version, clean_c[2:]) <= 0
        elif clean_c.startswith("<"):
            return cls.compare_versions(version, clean_c[1:]) < 0
        elif clean_c.startswith("==") or clean_c.startswith("="):
            base_v = clean_c.replace("==", "").replace("=", "").strip()
            return cls.compare_versions(version, base_v) == 0

        # Direct match or prefix
        return cls.compare_versions(version, clean_c) == 0

    @classmethod
    def find_version_conflicts(cls, dependencies: List[Any]) -> List[Dict[str, Any]]:
        """Detects version conflicts where multiple packages require incompatible versions of the same dependency."""
        by_name: Dict[str, List[Any]] = {}
        conflicts = []

        for dep in dependencies:
            by_name.setdefault(dep.normalized_name, []).append(dep)

        for norm_name, dep_list in by_name.items():
            versions = set(d.version for d in dep_list if d.version)
            if len(versions) > 1:
                conflicts.append({
                    "package_name": norm_name,
                    "versions_found": sorted(list(versions)),
                    "count": len(dep_list),
                    "details": f"Multiple conflicting versions found for package {norm_name}: {sorted(list(versions))}",
                })

        return conflicts
