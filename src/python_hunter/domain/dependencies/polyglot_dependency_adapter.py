"""Polyglot Dependency Adapter for static manifest parsing across ecosystem package managers."""

import os
import json
import re
from dataclasses import dataclass
from typing import List, Dict, Any
from python_hunter.domain.language.models import Language


@dataclass
class DiscoveredDependency:
    package_name: str
    version: str
    ecosystem: str  # PyPI, npm, Maven, Go modules, crates.io, Composer, RubyGems
    language: Language
    is_direct: bool = True
    is_production: bool = True
    vulnerability_status: str = "SAFE"
    advisory_id: str = ""
    severity: str = "NONE"


class PolyglotDependencyAdapter:
    """Parses manifest files for dependencies across all supported ecosystems without executing build commands."""

    @staticmethod
    def parse_workspace_dependencies(workspace_path: str) -> List[DiscoveredDependency]:
        deps: List[DiscoveredDependency] = []
        if not os.path.exists(workspace_path):
            return deps

        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)

                # 1. Maven (pom.xml)
                if file_name == "pom.xml":
                    deps.extend(PolyglotDependencyAdapter._parse_pom_xml(full_path))

                # 2. Gradle (build.gradle)
                elif file_name in ("build.gradle", "build.gradle.kts"):
                    deps.extend(PolyglotDependencyAdapter._parse_build_gradle(full_path))

                # 3. Go Modules (go.mod)
                elif file_name == "go.mod":
                    deps.extend(PolyglotDependencyAdapter._parse_go_mod(full_path))

                # 4. Cargo (Cargo.toml)
                elif file_name == "Cargo.toml":
                    deps.extend(PolyglotDependencyAdapter._parse_cargo_toml(full_path))

                # 5. Composer (composer.json)
                elif file_name == "composer.json":
                    deps.extend(PolyglotDependencyAdapter._parse_composer_json(full_path))

                # 6. Bundler (Gemfile)
                elif file_name == "Gemfile":
                    deps.extend(PolyglotDependencyAdapter._parse_gemfile(full_path))

                # 7. PyPI (requirements.txt)
                elif file_name == "requirements.txt":
                    deps.extend(PolyglotDependencyAdapter._parse_requirements_txt(full_path))

                # 8. npm (package.json)
                elif file_name == "package.json":
                    deps.extend(PolyglotDependencyAdapter._parse_package_json(full_path))

        return deps

    @staticmethod
    def _parse_pom_xml(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            artifacts = re.findall(r'<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?', content)
            for art, ver in artifacts:
                deps.append(DiscoveredDependency(
                    package_name=art,
                    version=ver or "latest",
                    ecosystem="Maven",
                    language=Language.JAVA,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_build_gradle(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            impls = re.findall(r'implementation\s+[\'"]([^\':]+):([^\':]+):([^\':]+)[\'"]', content)
            for group, art, ver in impls:
                deps.append(DiscoveredDependency(
                    package_name=f"{group}:{art}",
                    version=ver,
                    ecosystem="Gradle",
                    language=Language.JAVA,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_go_mod(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            requires = re.findall(r'^\s*([a-zA-Z0-9\.\-_/]+)\s+(v[0-9\.]+)', content, re.MULTILINE)
            for pkg, ver in requires:
                deps.append(DiscoveredDependency(
                    package_name=pkg,
                    version=ver,
                    ecosystem="Go modules",
                    language=Language.GO,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_cargo_toml(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            crates = re.findall(r'^([a-zA-Z0-9\-_]+)\s*=\s*[\'"]([0-9\.]+)[\'"]', content, re.MULTILINE)
            for crate, ver in crates:
                deps.append(DiscoveredDependency(
                    package_name=crate,
                    version=ver,
                    ecosystem="crates.io",
                    language=Language.RUST,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_composer_json(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            requires = data.get("require", {})
            for pkg, ver in requires.items():
                if pkg != "php":
                    deps.append(DiscoveredDependency(
                        package_name=pkg,
                        version=str(ver),
                        ecosystem="Composer",
                        language=Language.PHP,
                    ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_gemfile(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            gems = re.findall(r'gem\s+[\'"]([^\'"]+)[\'"](?:\s*,\s*[\'"]([^\'"]+)[\'"])?', content)
            for gem, ver in gems:
                deps.append(DiscoveredDependency(
                    package_name=gem,
                    version=ver or "latest",
                    ecosystem="RubyGems",
                    language=Language.RUBY,
                ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_requirements_txt(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = re.split(r'==|>=|<=', line)
                        pkg = parts[0].strip()
                        ver = parts[1].strip() if len(parts) > 1 else "latest"
                        deps.append(DiscoveredDependency(
                            package_name=pkg,
                            version=ver,
                            ecosystem="PyPI",
                            language=Language.PYTHON,
                        ))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_package_json(file_path: str) -> List[DiscoveredDependency]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            dependencies = data.get("dependencies", {})
            for pkg, ver in dependencies.items():
                deps.append(DiscoveredDependency(
                    package_name=pkg,
                    version=str(ver),
                    ecosystem="npm",
                    language=Language.TYPESCRIPT,
                ))
        except Exception:
            pass
        return deps
