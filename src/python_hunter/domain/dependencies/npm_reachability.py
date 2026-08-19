"""NPM Dependency Reachability Analyzer."""

from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.ir.models import SecurityIR


class NPMReachabilityAnalyzer:
    """Traces JavaScript/TypeScript imports against installed NPM dependencies."""

    def analyze_reachability(self, ir: SecurityIR, inventory: DependencyInventory) -> dict[str, bool]:
        """Determine reachability status (imported vs unreferenced) for installed NPM packages."""
        imported_packages = set()

        # Extract imported package names from calls and symbols in SecurityIR
        for call in ir.calls:
            callee_base = call.callee.split(".")[0]
            imported_packages.add(callee_base)

        reachability_map = {}
        for dep in inventory.dependencies:
            reachability_map[dep.name] = dep.name in imported_packages

        return reachability_map
