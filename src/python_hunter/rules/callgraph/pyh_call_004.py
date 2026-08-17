"""Security Rule PYH-CALL-004: Security Sink Reachability."""

from python_hunter.domain.callgraph.models import ReachabilityResult
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding


class PYHCall004SecuritySinkReachability:
    """Detects when an application entry point can reach a dangerous security sink through call graph execution paths."""

    id = "PYH-CALL-004"
    name = "Security Sink Reachability"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.INJECTION

    def evaluate_reachability(self, reachability: ReachabilityResult) -> Finding | None:
        """Evaluate call graph reachability result."""
        if reachability.is_reachable and reachability.call_path:
            ep = reachability.entry_point
            path_str = " -> ".join(reachability.call_path)
            loc = ep.location
            return Finding(
                rule_id=self.id,
                severity=self.severity,
                confidence=reachability.confidence,
                category=self.category,
                title=f"Security Sink Reachable from Entry Point: {ep.name}",
                description=f"Application entry point '{ep.qualified_name}' can reach security sink '{reachability.target_sink_name}' via call path: {path_str}",
                file_path=ep.file_path,
                location=loc,
                evidence=f"Entry: {ep.qualified_name}\nPath: {path_str}\nSink: {reachability.target_sink_name}",
                remediation="Sanitize untrusted inputs along the execution call path before reaching dangerous operations.",
            )
        return None
