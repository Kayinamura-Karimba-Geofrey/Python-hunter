"""Application Use Case for Static Dataflow & Taint Analysis."""

from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.taint.config import TaintConfig
from python_hunter.domain.taint.engine import TaintAnalysisEngine
from python_hunter.domain.taint.models import TaintFlow
from python_hunter.rules.taint import (
    PYHTaintCMD001,
    PYHTaintCode001,
    PYHTaintPath001,
    PYHTaintSQL001,
    PYHTaintSSRF001,
    PYHTaintTemplate001,
)


class AnalyzeTaintUseCase:
    """Orchestrates AST retrieval, static dataflow taint propagation, flow path extraction, and security finding generation."""

    def __init__(
        self,
        ast_use_case: AnalyzeASTUseCase | None = None,
        config: TaintConfig | None = None,
    ) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.config = config or TaintConfig()
        self.engine = TaintAnalysisEngine(config=self.config)

        # Rule evaluators
        self.rule_sql = PYHTaintSQL001()
        self.rule_cmd = PYHTaintCMD001()
        self.rule_path = PYHTaintPath001()
        self.rule_ssrf = PYHTaintSSRF001()
        self.rule_code = PYHTaintCode001()
        self.rule_template = PYHTaintTemplate001()

    def execute(
        self, target_path: str, rule_filter: str | None = None
    ) -> dict[str, Any]:
        """Execute static taint dataflow analysis on target project path."""
        ast_summary = self.ast_use_case.execute(target_path)

        all_flows: list[TaintFlow] = []
        for doc in ast_summary.documents:
            flows = self.engine.analyze_document(doc)
            all_flows.extend(flows)

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for flow in all_flows:
            # Map vulnerability rule ID to evaluator
            evaluator = None
            if flow.vulnerability_type == "PYH-TAINT-SQL-001":
                evaluator = self.rule_sql
            elif flow.vulnerability_type == "PYH-TAINT-CMD-001":
                evaluator = self.rule_cmd
            elif flow.vulnerability_type == "PYH-TAINT-PATH-001":
                evaluator = self.rule_path
            elif flow.vulnerability_type == "PYH-TAINT-SSRF-001":
                evaluator = self.rule_ssrf
            elif flow.vulnerability_type == "PYH-TAINT-CODE-001":
                evaluator = self.rule_code
            elif flow.vulnerability_type == "PYH-TAINT-TEMPLATE-001":
                evaluator = self.rule_template
            else:
                evaluator = self.rule_sql

            if rule_filter and evaluator.id != rule_filter:
                continue

            finding = evaluator.evaluate_flow(flow)
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                findings.append(finding)

        summary_counts = {
            "files_analyzed": ast_summary.files_analyzed,
            "total_flows_discovered": len(all_flows),
            "taint_findings_count": len(findings),
        }

        return {
            "target_path": target_path,
            "ast_summary": ast_summary,
            "summary_counts": summary_counts,
            "flows": all_flows,
            "findings": findings,
        }
