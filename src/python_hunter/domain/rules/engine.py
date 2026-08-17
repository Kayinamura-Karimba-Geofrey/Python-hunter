"""Security Rule Engine Execution Orchestrator."""

import time
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.rules.models import RuleResult, SecurityRule
from python_hunter.domain.rules.registry import RuleRegistry


class SecurityRuleEngine:
    """Orchestrates security rule execution, error isolation, metrics, and finding deduplication."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry()

    def evaluate_rules(
        self, ast_summary: ASTAnalysisSummary, context: AnalysisContext
    ) -> tuple[list[Finding], list[RuleResult]]:
        """Execute all enabled rules against AST summary, handling errors and deduplicating findings."""
        all_results: list[RuleResult] = []
        raw_findings: list[Finding] = []

        for rule in self.registry.enabled_rules():
            start_t = time.perf_counter()
            try:
                findings = rule.evaluate(ast_summary, context)
                duration_ms = (time.perf_counter() - start_t) * 1000.0
                res = RuleResult(rule_id=rule.id, findings=findings, execution_time_ms=duration_ms)
                all_results.append(res)
                raw_findings.extend(findings)
            except Exception as e:
                duration_ms = (time.perf_counter() - start_t) * 1000.0
                res = RuleResult(rule_id=rule.id, findings=[], execution_time_ms=duration_ms, error=str(e))
                all_results.append(res)

        # Deduplicate findings based on SHA-256 fingerprint
        dedup_findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for f in raw_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                dedup_findings.append(f)

        return dedup_findings, all_results
