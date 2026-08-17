from python_hunter.domain.callgraph.models import CallSite
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding


class PYHCall001UnresolvedDynamicCall:
    """Detects function call invocations that cannot be statically resolved."""

    id = "PYH-CALL-001"
    name = "Unresolved Dynamic Call"
    severity = Severity.INFO
    confidence = Confidence.LOW
    category = Category.OTHER

    def evaluate_call_site(self, call_site: CallSite) -> Finding | None:
        """Evaluate if a call site represents an unresolved dynamic call."""
        if call_site.confidence == Confidence.LOW or not call_site.candidate_qualified_names:
            loc = call_site.location
            file_path = loc.file_path if loc else "unknown"
            return Finding(
                rule_id=self.id,
                severity=self.severity,
                confidence=self.confidence,
                category=self.category,
                title=f"Unresolved Dynamic Call: {call_site.callee_name}()",
                description=f"Call invocation '{call_site.callee_name}()' in '{call_site.caller_qualified_name}' could not be statically resolved to a known function.",
                file_path=file_path,
                location=loc,
                evidence=f"{call_site.caller_qualified_name} -> {call_site.callee_name}()",
                remediation="Ensure target functions are explicitly imported or defined statically. Avoid dynamic string evaluation or reflection where static calls are possible.",
            )
        return None
