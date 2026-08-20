"""Declarative Rule DSL for defining security rules without modifying Python code."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from python_hunter.domain.semantics.taint_registries import SinkCategory, SourceCategory


@dataclass
class RuleCondition:
    category: str
    pattern: str
    is_required: bool = True


@dataclass
class DeclarativeSecurityRule:
    rule_id: str
    version: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe: str
    owasp: str
    remediation: str
    sources: List[RuleCondition] = field(default_factory=list)
    sinks: List[RuleCondition] = field(default_factory=list)
    sanitizers: List[RuleCondition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeclarativeSecurityRule":
        return cls(
            rule_id=data["rule_id"],
            version=data.get("version", "1.0.0"),
            title=data["title"],
            description=data.get("description", ""),
            severity=data.get("severity", "HIGH"),
            cwe=data.get("cwe", "CWE-20"),
            owasp=data.get("owasp", "A03:2021-Injection"),
            remediation=data.get("remediation", ""),
            sources=[RuleCondition(**s) for s in data.get("sources", [])],
            sinks=[RuleCondition(**s) for s in data.get("sinks", [])],
            sanitizers=[RuleCondition(**s) for s in data.get("sanitizers", [])],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation,
        }
