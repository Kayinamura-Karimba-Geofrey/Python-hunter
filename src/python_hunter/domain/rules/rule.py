"""Security Rule Domain Model."""

from dataclasses import dataclass, field
from typing import Any
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.exceptions.base import ValidationError


@dataclass(frozen=True)
class Rule:
    """Security rule definition and metadata."""

    rule_id: str
    name: str
    description: str
    category: Category
    severity: Severity
    confidence: Confidence
    cwe: str = "CWE-200"
    owasp: str = "A03:2021-Injection"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    version: str = "1.0.0"
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.strip():
            raise ValidationError("rule_id cannot be empty")
        if not self.name or not self.name.strip():
            raise ValidationError("name cannot be empty", {"rule_id": self.rule_id})
