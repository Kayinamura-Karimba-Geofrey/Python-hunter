"""Security Rule PYH-CALL-002: Potentially Unreachable Security Function."""

from python_hunter.domain.callgraph.models import Symbol
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding


class PYHCall002UnreachableSecurityFunction:
    """Detects security-critical functions that are statically unreachable from any application entry point."""

    id = "PYH-CALL-002"
    name = "Potentially Unreachable Security Function"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    category = Category.OTHER

    def evaluate_unreachable_symbol(self, symbol: Symbol) -> Finding | None:
        """Evaluate if an unreachable symbol is a security-critical function."""
        sec_keywords = ["auth", "login", "check_permission", "encrypt", "validate_token", "sanitize"]
        if any(kw in symbol.name.lower() for kw in sec_keywords):
            loc = symbol.location
            file_path = symbol.file_path
            return Finding(
                rule_id=self.id,
                severity=self.severity,
                confidence=self.confidence,
                category=self.category,
                title=f"Potentially Unreachable Security Function: {symbol.name}",
                description=f"Security function '{symbol.qualified_name}' is not reachable from any discovered application entry point.",
                file_path=file_path,
                location=loc,
                evidence=symbol.qualified_name,
                remediation="Ensure security validation functions are invoked along critical request paths. Remove dead security code if no longer required.",
            )
        return None
