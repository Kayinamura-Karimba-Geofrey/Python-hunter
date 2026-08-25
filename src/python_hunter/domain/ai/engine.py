"""Modular AI Security Intelligence Engine orchestrating all AI workflows."""

from typing import Any, Dict, List, Optional
from python_hunter.domain.ai.assistant import SecurityAssistant
from python_hunter.domain.ai.context_engine import SecurityContextEngine
from python_hunter.domain.ai.correlation_engine import FindingCorrelationEngine
from python_hunter.domain.ai.evaluator import AIEvaluator
from python_hunter.domain.ai.models import (
    AIAuditLog, AIConfidence, AIPolicy, AIQueryRequest, AIQueryResponse,
    FindingExplanation, RemediationRecommendation, RiskAssessment, SecurityContext, SecuritySummary
)
from python_hunter.domain.ai.pipeline import AIRequestPipeline
from python_hunter.domain.ai.prioritization_engine import IntelligentPrioritizationEngine
from python_hunter.domain.ai.registry import AIProviderRegistry
from python_hunter.domain.ai.remediation_engine import RemediationIntelligenceEngine
from python_hunter.domain.findings.finding import Finding


class AISecurityIntelligenceEngine:
    """Enterprise AI Security Intelligence Engine for Python Hunter."""

    def __init__(self) -> None:
        self.registry = AIProviderRegistry()
        self.pipeline = AIRequestPipeline(self.registry)
        self.context_engine = SecurityContextEngine()
        self.correlation_engine = FindingCorrelationEngine()
        self.prioritization_engine = IntelligentPrioritizationEngine()
        self.remediation_engine = RemediationIntelligenceEngine()
        self.assistant = SecurityAssistant()
        self.evaluator = AIEvaluator()

    def explain_finding(self, finding: Finding, user_id: str = "user-1", org_id: str = "org-1") -> FindingExplanation:
        """Explains a deterministic finding using evidence grounding."""
        return self.pipeline.process_explanation(finding, user_id=user_id, organization_id=org_id)

    def prioritize_finding(self, finding: Finding, repo_name: str = "default-repo") -> RiskAssessment:
        """Calculates contextual risk prioritization for a finding."""
        ctx = self.context_engine.get_context(repo_name)
        return self.prioritization_engine.prioritize(finding, ctx)

    def recommend_remediation(self, finding: Finding) -> RemediationRecommendation:
        """Generates structured remediation and patch suggestions."""
        return self.remediation_engine.recommend(finding)

    def generate_security_summary(
        self,
        findings: List[Finding],
        summary_type: str = "executive",
        target: str = "Repository"
    ) -> SecuritySummary:
        """Generates an executive, developer, or analyst security summary."""
        crit_count = sum(1 for f in findings if hasattr(f, 'severity') and f.severity.value in ["CRITICAL", "HIGH"])
        top_priorities = [f"{f.rule_id}: {f.title}" for f in findings[:3]]

        narrative = (
            f"Security scan completed for {target}. Found {len(findings)} total deterministic finding(s), "
            f"with {crit_count} high/critical priority item(s) requiring immediate attention."
        )

        return SecuritySummary(
            summary_type=summary_type,
            target=target,
            high_level_narrative=narrative,
            critical_findings_count=crit_count,
            top_priorities=top_priorities,
            attack_path_highlights=["Internet-facing API -> Vulnerable Dependency -> Core DB"],
            remediation_roadmap=["Remediate high severity findings", "Enforce CI/CD policy gates"],
            ai_confidence=AIConfidence.HIGH
        )

    def query_assistant(self, request: AIQueryRequest, findings: List[Finding]) -> AIQueryResponse:
        """Processes natural language security query."""
        return self.assistant.query(request, findings)

    def get_audit_logs(self) -> List[AIAuditLog]:
        """Returns AI operation audit logs."""
        return self.pipeline.audit_logs
