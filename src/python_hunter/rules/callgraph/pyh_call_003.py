"""Security Rule PYH-CALL-003: Circular Import Dependency Detected."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding


class PYHCall003CircularImportDependency:
    """Detects circular import dependencies across project modules."""

    id = "PYH-CALL-003"
    name = "Circular Import Dependency"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.OTHER

    def evaluate_import_cycle(self, cycle_modules: list[str]) -> Finding:
        """Evaluate a discovered import dependency cycle."""
        cycle_str = " -> ".join(cycle_modules)
        first_mod = cycle_modules[0]
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Circular Import Dependency: {first_mod}",
            description=f"Circular import dependency cycle detected: {cycle_str}",
            file_path=first_mod,
            location=None,
            evidence=cycle_str,
            remediation="Refactor circular module imports to prevent runtime import failures. Move shared data structures or functions into a separate utility module.",
        )
