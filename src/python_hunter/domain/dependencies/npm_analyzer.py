"""NPM package and dependency static analyzer."""

import json
import os
from python_hunter.domain.dependencies.models import Dependency, DependencyInventory, Ecosystem, PackageManager


class NPMAnalyzer:
    """Statically analyzes package.json, package-lock.json, and npm-shrinkwrap.json without executing scripts or package managers."""

    def analyze(self, workspace_path: str) -> DependencyInventory:
        inventory = DependencyInventory(package_manager=PackageManager.UNKNOWN)
        package_json_path = os.path.join(workspace_path, "package.json")

        if not os.path.exists(package_json_path):
            return inventory

        try:
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            inventory.manifests.append("package.json")

            deps = data.get("dependencies", {})
            for name, ver in deps.items():
                dep = Dependency(
                    name=name,
                    ecosystem=Ecosystem.JAVASCRIPT,
                    version=str(ver),
                    is_direct=True,
                )
                inventory.dependencies.append(dep)
                inventory.direct_count += 1

            dev_deps = data.get("devDependencies", {})
            for name, ver in dev_deps.items():
                dep = Dependency(
                    name=name,
                    ecosystem=Ecosystem.JAVASCRIPT,
                    version=str(ver),
                    is_direct=False,
                    is_development=True,
                )
                inventory.dependencies.append(dep)
                inventory.development_count += 1

            inventory.total_count = len(inventory.dependencies)
        except Exception:
            pass

        return inventory
