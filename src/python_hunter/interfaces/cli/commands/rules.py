"""CLI Command handler for Security Rules management."""

import json
import sys
from typing import Any
from python_hunter.rules.ast import get_default_registry


def run_rules_list_command() -> int:
    """Print list of registered security rules."""
    registry = get_default_registry()
    rules = registry.get_all()

    sys.stdout.write("\n=== Python Hunter Security Rules ===\n")
    sys.stdout.write(f"{'Rule ID':<15} {'Severity':<12} {'Status':<10} {'Name'}\n")
    sys.stdout.write("-" * 75 + "\n")

    for r in rules:
        status = "ENABLED" if r.enabled else "DISABLED"
        sys.stdout.write(f"{r.id:<15} {r.severity.value:<12} {status:<10} {r.name}\n")

    sys.stdout.write("\nTotal rules registered: " + str(len(rules)) + "\n\n")
    return 0


def run_rules_info_command(rule_id: str) -> int:
    """Print detailed metadata for a specific rule ID."""
    registry = get_default_registry()
    rule = registry.get(rule_id)

    if not rule:
        sys.stderr.write(f"Error: Security rule ID '{rule_id}' not found.\n")
        return 1

    sys.stdout.write(f"\n=== Security Rule Details: {rule.id} ===\n")
    sys.stdout.write(f"Name:        {rule.name}\n")
    sys.stdout.write(f"Severity:    {rule.severity.value}\n")
    sys.stdout.write(f"Confidence:  {rule.confidence.value}\n")
    sys.stdout.write(f"Category:    {rule.category.value}\n")
    sys.stdout.write(f"CWE:         {rule.cwe or 'N/A'}\n")
    sys.stdout.write(f"OWASP:       {rule.owasp or 'N/A'}\n")
    sys.stdout.write(f"Status:      {'ENABLED' if rule.enabled else 'DISABLED'}\n")
    sys.stdout.write(f"Description: {rule.description}\n")
    sys.stdout.write(f"Remediation: {rule.remediation}\n\n")
    return 0
