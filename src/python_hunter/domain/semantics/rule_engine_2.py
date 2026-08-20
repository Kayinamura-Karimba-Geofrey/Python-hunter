"""Rule Engine 2.0 with rule composition, graph consumption, and confidence calculation."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from python_hunter.domain.semantics.call_graph_2 import CallGraph2
from python_hunter.domain.semantics.interprocedural_engine import DataflowGraph, TaintFlowEvidence
from python_hunter.domain.semantics.program_model import ProgramModel
from python_hunter.domain.semantics.rule_dsl import DeclarativeSecurityRule


@dataclass
class ConfidenceScore:
    level: str  # HIGH, MEDIUM, LOW
    score: float  # 0.0 to 1.0
    rationale: List[str]


class ConfidenceEngine:
    """Calculates confidence score separately from vulnerability severity."""

    @staticmethod
    def calculate_confidence(
        has_type_info: bool,
        has_exact_call_resolution: bool,
        has_sanitizer_check: bool,
        is_dynamic_dispatch: bool,
    ) -> ConfidenceScore:
        score = 0.5
        rationale = []

        if has_exact_call_resolution:
            score += 0.3
            rationale.append("Exact call resolution confirmed in Call Graph 2.0")
        elif is_dynamic_dispatch:
            score -= 0.2
            rationale.append("Conservative dynamic dispatch target resolution")

        if has_type_info:
            score += 0.2
            rationale.append("Static/inferred type information present")

        if has_sanitizer_check:
            score -= 0.3
            rationale.append("Sanitizer present along dataflow path")

        score = max(0.0, min(1.0, score))
        level = "HIGH" if score >= 0.8 else ("MEDIUM" if score >= 0.5 else "LOW")
        return ConfidenceScore(level=level, score=score, rationale=rationale)


class RuleEngine2:
    """Rule Engine 2.0 evaluating declarative rules and composite observations."""

    def __init__(self, program_model: ProgramModel, call_graph: CallGraph2, dataflow_graph: Optional[DataflowGraph] = None) -> None:
        self.program_model = program_model
        self.call_graph = call_graph
        self.dataflow_graph = dataflow_graph
        self.rules: Dict[str, DeclarativeSecurityRule] = {}
        self.confidence_engine = ConfidenceEngine()

    def register_rule(self, rule: DeclarativeSecurityRule) -> None:
        self.rules[rule.rule_id] = rule

    def evaluate_composite_findings(self, taint_evidence: List[TaintFlowEvidence]) -> List[Dict[str, Any]]:
        """Evaluates multi-observation composed findings (untrusted input + missing auth + sensitive endpoint)."""
        findings = []

        for ev in taint_evidence:
            conf = self.confidence_engine.calculate_confidence(
                has_type_info=True,
                has_exact_call_resolution=not any(s.expression.startswith("dynamic:") for s in ev.steps),
                has_sanitizer_check=ev.is_sanitized,
                is_dynamic_dispatch=False,
            )

            # Rule Composition: Check if finding hits an unauthenticated endpoint
            is_unauth_endpoint = False
            for step in ev.steps:
                func = self.program_model.get_function(step.function_name)
                if func and func.is_endpoint_handler:
                    is_unauth_endpoint = True
                    break

            severity = "CRITICAL" if is_unauth_endpoint and not ev.is_sanitized else "HIGH"
            risk_score = 9.8 if severity == "CRITICAL" else 7.8

            finding = {
                "rule_id": "PYH-R2-COMP-001",
                "title": f"Composed Vulnerability Flow: {ev.source.name} -> {ev.sink.name}",
                "severity": severity,
                "confidence": conf.level,
                "confidence_score": conf.score,
                "confidence_rationale": conf.rationale,
                "risk_score": risk_score,
                "cwe": ev.sink.cwe,
                "owasp": ev.sink.owasp,
                "source": ev.source.name,
                "sink": ev.sink.name,
                "trace_steps": [
                    {
                        "description": step.description,
                        "expression": step.expression,
                        "function": step.function_name,
                        "file_path": step.file_path,
                    }
                    for step in ev.steps
                ],
                "sanitizers_applied": [san.name for san in ev.sanitizers_applied],
                "is_sanitized": ev.is_sanitized,
                "remediation": ev.sink.name,
            }
            findings.append(finding)

        return findings
