"""Static NPM Semver Range Evaluator."""

import re


class NPMSemver:
    """Evaluates NPM semver version range expressions statically without external binaries."""

    @staticmethod
    def parse_version(ver_str: str) -> tuple[int, int, int]:
        """Parse clean version tuple (major, minor, patch)."""
        clean = re.sub(r"[^\d.]", "", ver_str.split("-")[0])
        parts = [int(p) for p in clean.split(".") if p.isdigit()]
        while len(parts) < 3:
            parts.append(0)
        return (parts[0], parts[1], parts[2])

    @classmethod
    def satisfies(cls, version: str, constraint: str) -> bool:
        """Check if an installed version satisfies an NPM semver constraint."""
        if not constraint or constraint == "*" or constraint == "latest":
            return True

        v_tuple = cls.parse_version(version)

        # Handle OR ranges (e.g. "^1.0.0 || ^2.0.0")
        if "||" in constraint:
            sub_constraints = [c.strip() for c in constraint.split("||")]
            return any(cls.satisfies(version, sub) for sub in sub_constraints)

        # Caret range (^1.2.3 -> >=1.2.3 <2.0.0)
        if constraint.startswith("^"):
            base_tuple = cls.parse_version(constraint[1:])
            return v_tuple >= base_tuple and v_tuple[0] == base_tuple[0]

        # Tilde range (~1.2.3 -> >=1.2.3 <1.3.0)
        if constraint.startswith("~"):
            base_tuple = cls.parse_version(constraint[1:])
            return v_tuple >= base_tuple and v_tuple[0] == base_tuple[0] and v_tuple[1] == base_tuple[1]

        # Greater than or equal (>=1.2.3)
        if constraint.startswith(">="):
            return v_tuple >= cls.parse_version(constraint[2:])

        # Less than or equal (<=1.2.3)
        if constraint.startswith("<="):
            return v_tuple <= cls.parse_version(constraint[2:])

        # Greater than (>1.2.3)
        if constraint.startswith(">"):
            return v_tuple > cls.parse_version(constraint[1:])

        # Less than (<1.2.3)
        if constraint.startswith("<"):
            return v_tuple < cls.parse_version(constraint[1:])

        # Exact match
        return v_tuple == cls.parse_version(constraint)
