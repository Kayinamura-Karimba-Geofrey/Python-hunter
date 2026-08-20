"""PolyglotRuleRegistry for managing universal and language-specific security rules."""

from dataclasses import dataclass
from typing import Dict, List, Optional
from python_hunter.domain.language.models import Language


@dataclass
class RuleDefinition:
    rule_id: str
    title: str
    language: Language  # UNKNOWN for Universal IR rules
    framework: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # HIGH, MEDIUM, LOW
    cwe: str
    owasp: str
    description: str
    remediation_by_language: Dict[Language, str]
    enabled: bool = True
    version: str = "1.0.0"


class PolyglotRuleRegistry:
    """Registry managing rules across languages and universal IR security flow patterns."""

    def __init__(self) -> None:
        self._rules: Dict[str, RuleDefinition] = {}
        self._bootstrap_rules()

    def _bootstrap_rules(self) -> None:
        universal_sql_injection = RuleDefinition(
            rule_id="PYH-UNI-001",
            title="Universal SQL Injection Flow (User Input to Query Sink)",
            language=Language.UNKNOWN,  # Universal IR
            framework="Universal IR",
            category="INJECTION",
            severity="CRITICAL",
            confidence="HIGH",
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            description="Untrusted user input flows into a dynamic SQL query string construction.",
            remediation_by_language={
                Language.PYTHON: "Use parameterized queries e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).",
                Language.JAVA: "Use PreparedStatement or Spring JdbcTemplate with parameter placeholders.",
                Language.GO: "Use db.Query('SELECT * FROM users WHERE id = ?', userId).",
                Language.PHP: "Use PDO prepared statements e.g., $stmt->execute([':id' => $userId]).",
                Language.RUBY: "Use ActiveRecord parameter binding e.g., User.where('id = ?', params[:id]).",
            },
        )
        self.register_rule(universal_sql_injection)

    def register_rule(self, rule: RuleDefinition) -> None:
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[RuleDefinition]:
        return self._rules.get(rule_id)

    def list_rules(self, language: Optional[Language] = None) -> List[RuleDefinition]:
        if language is None:
            return list(self._rules.values())
        return [r for r in self._rules.values() if r.language in (language, Language.UNKNOWN)]
