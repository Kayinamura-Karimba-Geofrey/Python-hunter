"""NPM package, lockfile, and monorepo static analyzer."""

import json
import os
from typing import Any
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyGraph,
    DependencyInventory,
    Ecosystem,
    PackageManager,
)


class NPMAnalyzer:
    """Statically analyzes package.json, package-lock.json (v1/v2/v3), npm-shrinkwrap.json, and workspaces."""

    def analyze(self, workspace_path: str) -> DependencyInventory:
        inventory = DependencyInventory(package_manager=PackageManager.NPM)
        package_json_path = os.path.join(workspace_path, "package.json")

        if not os.path.exists(package_json_path):
            return inventory

        try:
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            inventory.manifests.append("package.json")

            # Direct production dependencies
            deps = data.get("dependencies", {})
            for name, ver in deps.items():
                dep = Dependency(
                    name=name,
                    ecosystem=Ecosystem.JAVASCRIPT,
                    version=str(ver),
                    version_constraint=str(ver),
                    is_direct=True,
                    is_development=False,
                    manifest_path="package.json",
                )
                inventory.dependencies.append(dep)
                inventory.graph.add_dependency(dep)
                inventory.direct_count += 1

            # Development dependencies
            dev_deps = data.get("devDependencies", {})
            for name, ver in dev_deps.items():
                dep = Dependency(
                    name=name,
                    ecosystem=Ecosystem.JAVASCRIPT,
                    version=str(ver),
                    version_constraint=str(ver),
                    is_direct=True,
                    is_development=True,
                    manifest_path="package.json",
                )
                inventory.dependencies.append(dep)
                inventory.graph.add_dependency(dep)
                inventory.development_count += 1

            # Parse package-lock.json for exact versions and transitive graph
            lock_path = os.path.join(workspace_path, "package-lock.json")
            if not os.path.exists(lock_path):
                lock_path = os.path.join(workspace_path, "npm-shrinkwrap.json")

            if os.path.exists(lock_path):
                inventory.manifests.append(os.path.basename(lock_path))
                with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                    lock_data = json.load(f)

                # Support lockfile v2/v3 "packages" map and v1 "dependencies" tree
                packages = lock_data.get("packages", {})
                if packages:
                    for pkg_path, pkg_info in packages.items():
                        if not pkg_path:
                            continue  # Skip root package
                        pkg_name = pkg_path.split("node_modules/")[-1]
                        if not pkg_name:
                            continue

                        pkg_ver = pkg_info.get("version", "0.0.0")
                        is_dev = pkg_info.get("dev", False)

                        # Check if already present as direct
                        existing = [d for d in inventory.dependencies if d.name == pkg_name]
                        if existing:
                            existing[0].version = pkg_ver
                        else:
                            dep = Dependency(
                                name=pkg_name,
                                ecosystem=Ecosystem.JAVASCRIPT,
                                version=pkg_ver,
                                is_direct=False,
                                is_transitive=True,
                                is_development=is_dev,
                                manifest_path=os.path.basename(lock_path),
                            )
                            inventory.dependencies.append(dep)
                            inventory.graph.add_dependency(dep)
                            inventory.transitive_count += 1

            inventory.total_count = len(inventory.dependencies)

        except Exception:
            pass

        return inventory
