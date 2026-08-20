"""Central Dependency Ecosystem Registry."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from python_hunter.domain.dependencies.models import Ecosystem, ManifestType, PackageManager


@dataclass
class EcosystemSpec:
    name: str
    ecosystem: Ecosystem
    package_managers: List[PackageManager]
    manifest_files: List[ManifestType]
    lock_files: List[ManifestType]
    default_registry_url: str


class DependencyEcosystemRegistry:
    """Registry managing supported ecosystems and their associated manifests."""

    def __init__(self) -> None:
        self.ecosystems: Dict[Ecosystem, EcosystemSpec] = {}
        self._bootstrap_ecosystems()

    def _bootstrap_ecosystems(self) -> None:
        specs = [
            EcosystemSpec(
                name="PyPI",
                ecosystem=Ecosystem.PYTHON,
                package_managers=[PackageManager.PIP, PackageManager.POETRY, PackageManager.PIPENV, PackageManager.UV, PackageManager.SETUPTOOLS],
                manifest_files=[ManifestType.REQUIREMENTS_TXT, ManifestType.PYPROJECT_TOML, ManifestType.PIPFILE, ManifestType.SETUP_PY],
                lock_files=[ManifestType.POETRY_LOCK, ManifestType.PIPFILE_LOCK, ManifestType.UV_LOCK],
                default_registry_url="https://pypi.org/pypi",
            ),
            EcosystemSpec(
                name="npm",
                ecosystem=Ecosystem.JAVASCRIPT,
                package_managers=[PackageManager.NPM, PackageManager.YARN, PackageManager.PNPM],
                manifest_files=[ManifestType.PACKAGE_JSON],
                lock_files=[ManifestType.PACKAGE_LOCK_JSON, ManifestType.YARN_LOCK, ManifestType.PNPM_LOCK],
                default_registry_url="https://registry.npmjs.org",
            ),
            EcosystemSpec(
                name="Maven",
                ecosystem=Ecosystem.MAVEN,
                package_managers=[PackageManager.MAVEN],
                manifest_files=[ManifestType.POM_XML],
                lock_files=[ManifestType.POM_XML],
                default_registry_url="https://repo1.maven.org/maven2",
            ),
            EcosystemSpec(
                name="Gradle",
                ecosystem=Ecosystem.GRADLE,
                package_managers=[PackageManager.GRADLE],
                manifest_files=[ManifestType.BUILD_GRADLE],
                lock_files=[ManifestType.GRADLE_LOCKFILE],
                default_registry_url="https://repo1.maven.org/maven2",
            ),
            EcosystemSpec(
                name="Go Modules",
                ecosystem=Ecosystem.GO_MODULES,
                package_managers=[PackageManager.GO],
                manifest_files=[ManifestType.GO_MOD],
                lock_files=[ManifestType.GO_SUM],
                default_registry_url="https://proxy.golang.org",
            ),
            EcosystemSpec(
                name="crates.io",
                ecosystem=Ecosystem.CRATES_IO,
                package_managers=[PackageManager.CARGO],
                manifest_files=[ManifestType.CARGO_TOML],
                lock_files=[ManifestType.CARGO_LOCK],
                default_registry_url="https://crates.io",
            ),
            EcosystemSpec(
                name="Composer",
                ecosystem=Ecosystem.COMPOSER,
                package_managers=[PackageManager.COMPOSER],
                manifest_files=[ManifestType.COMPOSER_JSON],
                lock_files=[ManifestType.COMPOSER_LOCK],
                default_registry_url="https://packagist.org",
            ),
            EcosystemSpec(
                name="RubyGems",
                ecosystem=Ecosystem.RUBYGEMS,
                package_managers=[PackageManager.BUNDLER],
                manifest_files=[ManifestType.GEMFILE],
                lock_files=[ManifestType.GEMFILE_LOCK],
                default_registry_url="https://rubygems.org",
            ),
        ]
        for spec in specs:
            self.ecosystems[spec.ecosystem] = spec

    def register_ecosystem(self, spec: EcosystemSpec) -> None:
        self.ecosystems[spec.ecosystem] = spec

    def get_spec(self, ecosystem: Ecosystem) -> Optional[EcosystemSpec]:
        return self.ecosystems.get(ecosystem)

    def detect_ecosystem_by_filename(self, filename: str) -> Optional[EcosystemSpec]:
        for spec in self.ecosystems.values():
            for m in spec.manifest_files + spec.lock_files:
                if filename.lower() == m.value.lower():
                    return spec
        return None
