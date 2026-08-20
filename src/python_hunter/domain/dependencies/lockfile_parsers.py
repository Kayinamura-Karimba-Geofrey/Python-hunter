"""Lockfile and Manifest Parsers across 8 dependency ecosystems."""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencySource,
    DependencyType,
    Ecosystem,
    ManifestType,
    PackageManager,
    SourceType,
)


class UniversalLockfileParser:
    """Parses manifest files and lockfiles for all supported package ecosystems."""

    @staticmethod
    def parse_file(file_path: str) -> List[Dependency]:
        filename = os.path.basename(file_path)
        
        if filename == "requirements.txt":
            return UniversalLockfileParser.parse_requirements_txt(file_path)
        elif filename in ("package.json", "package-lock.json"):
            return UniversalLockfileParser.parse_npm(file_path)
        elif filename in ("poetry.lock", "Pipfile.lock"):
            return UniversalLockfileParser.parse_python_lock(file_path)
        elif filename in ("pom.xml", "build.gradle"):
            return UniversalLockfileParser.parse_java(file_path)
        elif filename in ("go.mod", "go.sum"):
            return UniversalLockfileParser.parse_go(file_path)
        elif filename in ("Cargo.toml", "Cargo.lock"):
            return UniversalLockfileParser.parse_cargo(file_path)
        elif filename in ("composer.json", "composer.lock"):
            return UniversalLockfileParser.parse_composer(file_path)
        elif filename in ("Gemfile", "Gemfile.lock"):
            return UniversalLockfileParser.parse_ruby(file_path)
        else:
            return UniversalLockfileParser.parse_generic(file_path)

    @staticmethod
    def parse_requirements_txt(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str.startswith("#"):
                        continue
                    # Match name==version or name>=version
                    parts = re.split(r"(==|>=|<=|~=|>|<)", line_str, maxsplit=1)
                    name = parts[0].strip()
                    version = parts[2].strip() if len(parts) > 2 else ""
                    op = parts[1].strip() if len(parts) > 1 else ""
                    deps.append(Dependency(
                        name=name,
                        ecosystem=Ecosystem.PYTHON,
                        version=version if op == "==" else "",
                        version_constraint=f"{op}{version}" if op else "",
                        package_manager=PackageManager.PIP,
                        manifest_path=file_path,
                        is_direct=True,
                    ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_npm(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if "dependencies" in data:
                for pkg, ver in data["dependencies"].items():
                    if isinstance(ver, dict):  # package-lock.json format
                        version = ver.get("version", "")
                        integrity = ver.get("integrity", "")
                        is_dev = ver.get("dev", False)
                        deps.append(Dependency(
                            name=pkg,
                            ecosystem=Ecosystem.JAVASCRIPT,
                            version=version,
                            integrity_hash=integrity,
                            package_manager=PackageManager.NPM,
                            manifest_path=file_path,
                            is_direct=True,
                            is_development=is_dev,
                        ))
                    else:  # package.json format
                        deps.append(Dependency(
                            name=pkg,
                            ecosystem=Ecosystem.JAVASCRIPT,
                            version_constraint=str(ver),
                            package_manager=PackageManager.NPM,
                            manifest_path=file_path,
                            is_direct=True,
                        ))
            if "devDependencies" in data:
                for pkg, ver in data["devDependencies"].items():
                    deps.append(Dependency(
                        name=pkg,
                        ecosystem=Ecosystem.JAVASCRIPT,
                        version_constraint=str(ver) if not isinstance(ver, dict) else ver.get("version", ""),
                        package_manager=PackageManager.NPM,
                        manifest_path=file_path,
                        is_direct=True,
                        is_development=True,
                    ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_python_lock(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if file_path.endswith(".json") or "Pipfile.lock" in file_path:
                data = json.loads(content)
                default_deps = data.get("default", {})
                for name, info in default_deps.items():
                    ver = info.get("version", "").replace("==", "")
                    deps.append(Dependency(
                        name=name,
                        ecosystem=Ecosystem.PYTHON,
                        version=ver,
                        package_manager=PackageManager.PIPENV,
                        manifest_path=file_path,
                        is_direct=True,
                        integrity_hash=info.get("hashes", [""])[0] if info.get("hashes") else "",
                    ))
            else:  # poetry.lock simple block parse
                for block in content.split("[[package]]"):
                    if "name =" in block:
                        name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                        ver_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                        if name_match and ver_match:
                            deps.append(Dependency(
                                name=name_match.group(1),
                                ecosystem=Ecosystem.PYTHON,
                                version=ver_match.group(1),
                                package_manager=PackageManager.POETRY,
                                manifest_path=file_path,
                                is_direct=False,  # poetry.lock includes transitives
                                is_transitive=True,
                            ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_java(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # Regex match <groupId>:<artifactId>:<version> or implementation 'group:artifact:version'
            matches = re.findall(r"['\"]([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)['\"]", content)
            for group, artifact, ver in matches:
                deps.append(Dependency(
                    name=f"{group}:{artifact}",
                    ecosystem=Ecosystem.MAVEN if file_path.endswith(".xml") else Ecosystem.GRADLE,
                    version=ver,
                    package_manager=PackageManager.MAVEN if file_path.endswith(".xml") else PackageManager.GRADLE,
                    manifest_path=file_path,
                    is_direct=True,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_go(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str.startswith("require") or " v" in line_str:
                        parts = line_str.replace("require", "").strip().split()
                        if len(parts) >= 2:
                            pkg, ver = parts[0], parts[1]
                            deps.append(Dependency(
                                name=pkg,
                                ecosystem=Ecosystem.GO_MODULES,
                                version=ver,
                                package_manager=PackageManager.GO,
                                manifest_path=file_path,
                                is_direct=not line_str.endswith("// indirect"),
                                is_transitive=line_str.endswith("// indirect"),
                            ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_cargo(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for block in content.split("[[package]]"):
                if "name =" in block:
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_match and ver_match:
                        deps.append(Dependency(
                            name=name_match.group(1),
                            ecosystem=Ecosystem.CRATES_IO,
                            version=ver_match.group(1),
                            package_manager=PackageManager.CARGO,
                            manifest_path=file_path,
                            is_direct=True,
                        ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_composer(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            packages = data.get("packages", []) if "packages" in data else []
            if isinstance(data.get("require"), dict):
                for pkg, ver in data["require"].items():
                    if pkg != "php":
                        deps.append(Dependency(
                            name=pkg,
                            ecosystem=Ecosystem.COMPOSER,
                            version_constraint=str(ver),
                            package_manager=PackageManager.COMPOSER,
                            manifest_path=file_path,
                            is_direct=True,
                        ))
            for pkg in packages:
                if isinstance(pkg, dict) and "name" in pkg:
                    deps.append(Dependency(
                        name=pkg["name"],
                        ecosystem=Ecosystem.COMPOSER,
                        version=pkg.get("version", ""),
                        package_manager=PackageManager.COMPOSER,
                        manifest_path=file_path,
                        is_direct=False,
                        is_transitive=True,
                    ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_ruby(file_path: str) -> List[Dependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str.startswith("gem "):
                        parts = line_str.split(",")
                        gem_name = parts[0].replace("gem", "").replace("'", "").replace('"', "").strip()
                        ver = parts[1].replace("'", "").replace('"', "").strip() if len(parts) > 1 else ""
                        deps.append(Dependency(
                            name=gem_name,
                            ecosystem=Ecosystem.RUBYGEMS,
                            version_constraint=ver,
                            package_manager=PackageManager.BUNDLER,
                            manifest_path=file_path,
                            is_direct=True,
                        ))
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_generic(file_path: str) -> List[Dependency]:
        return []
