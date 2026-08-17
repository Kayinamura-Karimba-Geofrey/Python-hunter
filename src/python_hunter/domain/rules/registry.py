"""Security Rule Registry."""

from python_hunter.domain.common.enums import Category
from python_hunter.domain.exceptions.base import ValidationError
from python_hunter.domain.rules.models import SecurityRule


class RuleRegistry:
    """Central registry managing security rules, enforcing unique IDs and status lookups."""

    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}

    def register(self, rule: SecurityRule) -> None:
        """Register a security rule into the registry."""
        if not rule.id:
            raise ValidationError("Security rule must have a non-empty ID")
        if rule.id in self._rules:
            raise ValidationError(f"Rule ID '{rule.id}' is already registered", {"rule_id": rule.id})
        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the registry."""
        if rule_id in self._rules:
            del self._rules[rule_id]

    def get(self, rule_id: str) -> SecurityRule | None:
        """Get registered rule by ID."""
        return self._rules.get(rule_id)

    def get_all(self) -> list[SecurityRule]:
        """Return list of all registered rules."""
        return list(self._rules.values())

    def enabled_rules(self) -> list[SecurityRule]:
        """Return list of all enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def find_by_category(self, category: Category) -> list[SecurityRule]:
        """Find rules matching specific category."""
        return [r for r in self._rules.values() if r.category == category]
