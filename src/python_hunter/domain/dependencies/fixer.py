"""Dependency Fixer and Version Bumping Engine.

Safely updates vulnerable, unpinned, and policy-violating dependency versions
in requirements.txt, pyproject.toml, and package.json.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Any

from python_hunter.domain.dependencies.models import Dependency, DependencyInventory
from python_hunter.domain.dependencies.normalization import normalize_package_name
from python_hunter.domain.dependencies.remediation_engine import RemediationEngine
from python_hunter.domain.dependencies.vulnerability_intel import Advisory


@dataclass
class DependencyFixResult:
    """Outcome of an automated dependency fix operation."""

    file_path: str
    package_name: str
    old_version: str
    new_version: str
    reason: str
    applied: bool = True


class DependencyFixEngine:
    """Engine for applying targeted version bumps to project dependency manifests."""

    # Default baseline recommended stable versions for unpinned common packages
    DEFAULT_PINNED_VERSIONS: dict[str, str] = {
        "requests": "2.31.0",
        "urllib3": "2.0.7",
        "flask": "3.0.0",
        "django": "4.2.11",
        "fastapi": "0.109.2",
        "pydantic": "2.6.1",
        "jinja2": "3.1.3",
        "werkzeug": "3.0.1",
        "cryptography": "42.0.4",
        "pyyaml": "6.0.1",
        "pillow": "10.2.0",
        "aiohttp": "3.9.3",
        "numpy": "1.26.4",
        "pytest": "8.0.2",
        "pytest-cov": "4.1.0",
        "hypothesis": "6.99.0",
        "colorama": "0.4.6",
        "click": "8.1.7",
    }

    @classmethod
    def calculate_updates(
        cls,
        inventory: DependencyInventory,
        advisories: list[Advisory] | None = None,
        fix_unpinned: bool = True,
        fix_vulnerabilities: bool = True,
    ) -> dict[str, dict[str, Any]]:
        """Calculate necessary version bumps across inventory dependencies."""
        updates: dict[str, dict[str, Any]] = {}
        adv_by_pkg: dict[str, list[Advisory]] = {}

        if advisories:
            for adv in advisories:
                norm = normalize_package_name(adv.package_name)
                adv_by_pkg.setdefault(norm, []).append(adv)

        for dep in inventory.dependencies:
            norm_name = dep.normalized_name
            curr_ver = dep.version or dep.version_constraint or ""

            # 1. Check for vulnerabilities with available patches
            if fix_vulnerabilities and norm_name in adv_by_pkg:
                for adv in adv_by_pkg[norm_name]:
                    rec = RemediationEngine.generate_recommendation(dep, adv)
                    if rec.action == "UPGRADE" and rec.recommended_version:
                        updates[norm_name] = {
                            "package_name": dep.name,
                            "old_version": curr_ver,
                            "new_version": rec.recommended_version,
                            "reason": rec.reason,
                            "manifest_path": dep.manifest_path,
                        }
                        break

            # 2. Check for unpinned or overly broad dependencies
            if norm_name not in updates and fix_unpinned:
                is_unpinned = (
                    not curr_ver
                    or curr_ver.startswith(">=")
                    or curr_ver.startswith(">")
                    or curr_ver.startswith("^")
                    or curr_ver.startswith("~")
                    or curr_ver == "*"
                )
                if is_unpinned:
                    rec_ver = cls.DEFAULT_PINNED_VERSIONS.get(norm_name)
                    if not rec_ver and curr_ver and re.match(r"^[>=^~]*([0-9]+\.[0-9]+(\.[0-9]+)?)", curr_ver):
                        m = re.match(r"^[>=^~]*([0-9]+\.[0-9]+(\.[0-9]+)?)", curr_ver)
                        if m:
                            rec_ver = m.group(1)

                    if rec_ver:
                        updates[norm_name] = {
                            "package_name": dep.name,
                            "old_version": curr_ver or "unpinned",
                            "new_version": rec_ver,
                            "reason": f"Pin unconstrained dependency '{dep.name}' to verified stable release {rec_ver}.",
                            "manifest_path": dep.manifest_path,
                        }

        return updates

    @classmethod
    def fix_requirements_txt(
        cls,
        content: str,
        updates: dict[str, dict[str, Any]],
    ) -> tuple[str, list[DependencyFixResult]]:
        """Safely updates package versions in requirements.txt preserving comments and whitespace."""
        new_lines: list[str] = []
        applied_fixes: list[DependencyFixResult] = []

        for line in content.splitlines(keepends=True):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                new_lines.append(line)
                continue

            # Parse package name from requirement line
            match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", stripped)
            if not match:
                new_lines.append(line)
                continue

            raw_pkg, rest = match.groups()
            norm = normalize_package_name(raw_pkg)

            if norm in updates:
                upd = updates[norm]
                target_ver = upd["new_version"]

                # Extract trailing comments if any
                comment = ""
                if " #" in line:
                    comment = " #" + line.split(" #", 1)[1].rstrip("\r\n")

                ending = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
                new_line = f"{raw_pkg}=={target_ver}{comment}{ending}"
                new_lines.append(new_line)

                applied_fixes.append(
                    DependencyFixResult(
                        file_path="requirements.txt",
                        package_name=raw_pkg,
                        old_version=upd["old_version"],
                        new_version=target_ver,
                        reason=upd["reason"],
                    )
                )
            else:
                new_lines.append(line)

        return "".join(new_lines), applied_fixes

    @classmethod
    def fix_pyproject_toml(
        cls,
        content: str,
        updates: dict[str, dict[str, Any]],
    ) -> tuple[str, list[DependencyFixResult]]:
        """Safely updates package constraints in pyproject.toml string entries."""
        new_content = content
        applied_fixes: list[DependencyFixResult] = []

        for norm, upd in updates.items():
            pkg_name = upd["package_name"]
            target_ver = upd["new_version"]

            # Match standard PEP 621 dependencies list: "requests>=2.0.0" or "requests==..."
            pep621_pattern = rf'(["\']){re.escape(pkg_name)}([<>=!~^0-9.\-_]*)(["\'])'

            def _pep621_repl(m: re.Match[str]) -> str:
                quote = m.group(1)
                return f"{quote}{pkg_name}=={target_ver}{quote}"

            if re.search(pep621_pattern, new_content, re.IGNORECASE):
                new_content = re.sub(pep621_pattern, _pep621_repl, new_content, flags=re.IGNORECASE)
                applied_fixes.append(
                    DependencyFixResult(
                        file_path="pyproject.toml",
                        package_name=pkg_name,
                        old_version=upd["old_version"],
                        new_version=target_ver,
                        reason=upd["reason"],
                    )
                )
                continue

            # Match Poetry tool dependencies: requests = "^2.0.0"
            poetry_pattern = rf'({re.escape(pkg_name)}\s*=\s*)(["\'])[^"\']*(["\'])'

            def _poetry_repl(m: re.Match[str]) -> str:
                return f'{m.group(1)}"{target_ver}"'

            if re.search(poetry_pattern, new_content, re.IGNORECASE):
                new_content = re.sub(poetry_pattern, _poetry_repl, new_content, flags=re.IGNORECASE)
                applied_fixes.append(
                    DependencyFixResult(
                        file_path="pyproject.toml",
                        package_name=pkg_name,
                        old_version=upd["old_version"],
                        new_version=target_ver,
                        reason=upd["reason"],
                    )
                )

        return new_content, applied_fixes

    @classmethod
    def fix_package_json(
        cls,
        content: str,
        updates: dict[str, dict[str, Any]],
    ) -> tuple[str, list[DependencyFixResult]]:
        """Safely updates dependency versions in package.json preserving json structure."""
        applied_fixes: list[DependencyFixResult] = []
        try:
            data = json.loads(content)
        except Exception:
            return content, []

        modified = False
        for sec in ("dependencies", "devDependencies", "peerDependencies"):
            if sec in data and isinstance(data[sec], dict):
                for pkg, old_val in list(data[sec].items()):
                    norm = normalize_package_name(pkg)
                    if norm in updates:
                        upd = updates[norm]
                        target_ver = upd["new_version"]
                        data[sec][pkg] = target_ver
                        modified = True
                        applied_fixes.append(
                            DependencyFixResult(
                                file_path="package.json",
                                package_name=pkg,
                                old_version=str(old_val),
                                new_version=target_ver,
                                reason=upd["reason"],
                            )
                        )

        if modified:
            return json.dumps(data, indent=2) + "\n", applied_fixes
        return content, []
