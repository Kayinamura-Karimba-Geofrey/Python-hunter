"""Analyze Dependencies Application Use Case."""

import os
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyGraph,
    DependencyInventory,
    DependencyType,
    PackageManager,
    SourceType,
)
from python_hunter.domain.dependencies.providers import (
    CachedMetadataProvider,
    LocalMetadataProvider,
    PackageMetadataProvider,
)
from python_hunter.domain.findings.finding import Finding
from python_hunter.infrastructure.dependencies.parsers import get_all_manifest_parsers
from python_hunter.rules.dependencies import get_all_dependency_rules


class AnalyzeDependenciesUseCase:
    """Orchestrates third-party dependency discovery, graph building, rule evaluation, and findings."""

    def __init__(self, provider: PackageMetadataProvider | None = None) -> None:
        self.discovery_use_case = DiscoverProjectUseCase()
        self.parsers = get_all_manifest_parsers()
        self.rules = get_all_dependency_rules()
        self.provider = provider or CachedMetadataProvider(LocalMetadataProvider())

    def execute(self, target_path: str) -> dict[str, object]:
        """Perform comprehensive dependency analysis on a project directory or manifest file."""
        root_path = target_path
        if os.path.isfile(target_path):
            root_path = os.path.dirname(target_path) or "."
            manifest_files = [target_path]
            project_name = os.path.basename(root_path)
        else:
            manifest = self.discovery_use_case.discover(root_path)
            project_name = manifest.project_name
            manifest_files = [
                os.path.join(manifest.root_path, file_meta.relative_path)
                for file_meta in manifest.files
            ]

        discovered_deps: list[Dependency] = []
        parsed_manifests: set[str] = set()
        pkg_manager = PackageManager.UNKNOWN

        for file_path in manifest_files:
            rel_path = os.path.relpath(file_path, root_path)
            for parser in self.parsers:
                if parser.can_parse(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        deps = parser.parse(rel_path, content)
                        discovered_deps.extend(deps)
                        parsed_manifests.add(rel_path)
                        if pkg_manager == PackageManager.UNKNOWN:
                            pkg_manager = parser.package_manager
                    except Exception:
                        continue

        # Check metadata enrichment (e.g. yanked versions)
        for dep in discovered_deps:
            meta = self.provider.get_metadata(dep.name)
            if meta:
                if dep.version and dep.version in meta.yanked_versions:
                    dep.yanked = True
                    dep.yanked_reason = meta.yanked_versions[dep.version]

        # Build DependencyGraph
        graph = DependencyGraph()
        by_norm: dict[str, Dependency] = {}
        for dep in discovered_deps:
            by_norm[dep.normalized_name] = dep

        for dep in discovered_deps:
            child_names = dep.metadata.get("child_dependencies", [])
            graph.add_dependency(dep, child_names=child_names)

        # Build Inventory
        direct_count = sum(1 for d in discovered_deps if d.is_direct)
        transitive_count = sum(1 for d in discovered_deps if d.is_transitive)
        dev_count = sum(1 for d in discovered_deps if d.is_development)
        opt_count = sum(1 for d in discovered_deps if d.is_optional)
        vcs_count = sum(1 for d in discovered_deps if d.source.source_type == SourceType.VCS)
        url_count = sum(1 for d in discovered_deps if d.source.source_type == SourceType.URL)
        local_count = sum(1 for d in discovered_deps if d.source.source_type == SourceType.LOCAL)

        inventory = DependencyInventory(
            package_manager=pkg_manager,
            manifests=list(parsed_manifests),
            total_count=len(discovered_deps),
            direct_count=direct_count,
            transitive_count=transitive_count,
            development_count=dev_count,
            optional_count=opt_count,
            vcs_count=vcs_count,
            url_count=url_count,
            local_count=local_count,
            dependencies=discovered_deps,
            graph=graph,
        )

        # Evaluate rules & deduplicate findings
        all_findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(inventory, root_path)
                for f in rule_findings:
                    if f.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(f.fingerprint)
                        all_findings.append(f)
            except Exception:
                continue

        return {
            "project_name": project_name,
            "project_path": root_path,
            "manifests": list(parsed_manifests),
            "inventory": inventory,
            "findings": all_findings,
        }
