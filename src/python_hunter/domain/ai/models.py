"""Domain models for AI Security Intelligence Engine (Zero External Dependencies)."""

from datetime import datetime, timezone

from enum import Enum
from typing import Any, Dict, List, Optional


class PrivacyMode(str, Enum):
    """Privacy modes for AI processing."""
    STRICT_LOCAL = "STRICT_LOCAL"
    REDACTED_EXTERNAL = "REDACTED_EXTERNAL"
    ORGANIZATION_APPROVED_EXTERNAL = "ORGANIZATION_APPROVED_EXTERNAL"


class AIConfidence(str, Enum):
    """AI confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssetCriticality(str, Enum):
    """Business asset criticality levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InternetExposure(str, Enum):
    """Internet exposure levels."""
    INTERNAL = "INTERNAL"
    INTERNET_FACING = "INTERNET_FACING"
    UNKNOWN = "UNKNOWN"


class EnvironmentType(str, Enum):
    """Target runtime environment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class AIDecisionLevel(str, Enum):
    """AI decision authorization levels."""
    INFORMATIONAL = "INFORMATIONAL"
    ASSISTED = "ASSISTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"


class AIProviderConfig:
    """Configuration for an AI Provider."""
    def __init__(
        self,
        provider_id: str,
        name: str,
        enabled: bool = True,
        is_local: bool = True,
        model: str = "local-security-v1",
        temperature: float = 0.2,
        max_tokens: int = 1524,
        privacy_mode: PrivacyMode = PrivacyMode.STRICT_LOCAL,
        daily_budget_usd: float = 50.0,
        monthly_budget_usd: float = 1000.0
    ):
        self.provider_id = provider_id
        self.name = name
        self.enabled = enabled
        self.is_local = is_local
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.privacy_mode = privacy_mode
        self.daily_budget_usd = daily_budget_usd
        self.monthly_budget_usd = monthly_budget_usd


class SecurityContext:
    """Target security and business context."""
    def __init__(
        self,
        repository: str = "unknown",
        branch: str = "main",
        file_path: Optional[str] = None,
        asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
        internet_exposure: InternetExposure = InternetExposure.UNKNOWN,
        environment: EnvironmentType = EnvironmentType.DEVELOPMENT,
        business_impact: str = "Standard application operation",
        is_sensitive_project: bool = False,
        is_production: bool = False,
        owner: str = "security-team"
    ):
        self.repository = repository
        self.branch = branch
        self.file_path = file_path
        self.asset_criticality = asset_criticality
        self.internet_exposure = internet_exposure
        self.environment = environment
        self.business_impact = business_impact
        self.is_sensitive_project = is_sensitive_project
        self.is_production = is_production
        self.owner = owner


class FindingExplanation:
    """Structured AI explanation of a deterministic finding."""
    def __init__(
        self,
        finding_id: str,
        what_happened: str,
        why_dangerous: str,
        location_summary: str,
        attacker_possibilities: str,
        remediation_summary: str,
        confidence: AIConfidence,
        evidence_grounding: List[str],
        prompt_version: str = "v1.0"
    ):
        self.finding_id = finding_id
        self.what_happened = what_happened
        self.why_dangerous = why_dangerous
        self.location_summary = location_summary
        self.attacker_possibilities = attacker_possibilities
        self.remediation_summary = remediation_summary
        self.confidence = confidence
        self.evidence_grounding = evidence_grounding
        self.prompt_version = prompt_version


class RiskAssessment:
    """Risk intelligence and contextual prioritization output."""
    def __init__(
        self,
        finding_id: str,
        original_severity: str,
        contextual_priority: str,
        adjusted_score: float,
        why_high_risk: str,
        evidence_used: List[str],
        confidence: AIConfidence
    ):
        self.finding_id = finding_id
        self.original_severity = original_severity
        self.contextual_priority = contextual_priority
        self.adjusted_score = adjusted_score
        self.why_high_risk = why_high_risk
        self.evidence_used = evidence_used
        self.confidence = confidence


class RemediationRecommendation:
    """Structured remediation recommendation and optional patch suggestion."""
    def __init__(
        self,
        finding_id: str,
        recommended_fix: str,
        why_it_works: str,
        security_tradeoffs: str,
        possible_side_effects: str,
        suggested_patch: Optional[str] = None,
        is_ai_generated: bool = True,
        review_required: bool = True,
        confidence: AIConfidence = AIConfidence.HIGH
    ):
        self.finding_id = finding_id
        self.recommended_fix = recommended_fix
        self.why_it_works = why_it_works
        self.security_tradeoffs = security_tradeoffs
        self.possible_side_effects = possible_side_effects
        self.suggested_patch = suggested_patch
        self.is_ai_generated = is_ai_generated
        self.review_required = review_required
        self.confidence = confidence


class AttackPathAssessment:
    """Structured attack path evaluation."""
    def __init__(
        self,
        path_id: str,
        human_explanation: str,
        exploitability_reasoning: str,
        exposure_impact: str,
        privilege_level: str,
        rank_score: float,
        confidence: AIConfidence
    ):
        self.path_id = path_id
        self.human_explanation = human_explanation
        self.exploitability_reasoning = exploitability_reasoning
        self.exposure_impact = exposure_impact
        self.privilege_level = privilege_level
        self.rank_score = rank_score
        self.confidence = confidence


class SecuritySummary:
    """Executive, Developer, or Analyst Security Summary."""
    def __init__(
        self,
        summary_type: str,
        target: str,
        high_level_narrative: str,
        critical_findings_count: int,
        top_priorities: List[str],
        attack_path_highlights: List[str],
        remediation_roadmap: List[str],
        ai_confidence: AIConfidence
    ):
        self.summary_type = summary_type
        self.target = target
        self.high_level_narrative = high_level_narrative
        self.critical_findings_count = critical_findings_count
        self.top_priorities = top_priorities
        self.attack_path_highlights = attack_path_highlights
        self.remediation_roadmap = remediation_roadmap
        self.ai_confidence = ai_confidence


class AIQueryRequest:
    """Natural language security query request."""
    def __init__(
        self,
        query: str,
        organization_id: str,
        user_id: str,
        user_role: str = "developer"
    ):
        self.query = query
        self.organization_id = organization_id
        self.user_id = user_id
        self.user_role = user_role


class AIQueryResponse:
    """Authorized natural language query response."""
    def __init__(
        self,
        query: str,
        answer: str,
        structured_findings: Optional[List[Dict[str, Any]]] = None,
        tools_used: Optional[List[str]] = None,
        confidence: AIConfidence = AIConfidence.HIGH,
        evidence_references: Optional[List[str]] = None
    ):
        self.query = query
        self.answer = answer
        self.structured_findings = structured_findings or []
        self.tools_used = tools_used or []
        self.confidence = confidence
        self.evidence_references = evidence_references or []


class AISecurityScore:
    """AI Security Quality and Hallucination Score."""
    def __init__(
        self,
        grounding_score: float,
        correctness_score: float,
        safety_score: float,
        reliability_score: float,
        overall_quality_score: float
    ):
        self.grounding_score = grounding_score
        self.correctness_score = correctness_score
        self.safety_score = safety_score
        self.reliability_score = reliability_score
        self.overall_quality_score = overall_quality_score


class AIAuditLog:
    """Audit entry for AI operations."""
    def __init__(
        self,
        log_id: str,
        user_id: str,
        organization_id: str,
        provider_id: str,
        model: str,
        request_type: str,
        timestamp: Optional[datetime] = None,
        tools_used: Optional[List[str]] = None,
        status: str = "SUCCESS",
        tokens_used: int = 0,
        estimated_cost_usd: float = 0.0
    ):
        self.log_id = log_id
        self.user_id = user_id
        self.organization_id = organization_id
        self.provider_id = provider_id
        self.model = model
        self.request_type = request_type
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.tools_used = tools_used or []
        self.status = status
        self.tokens_used = tokens_used
        self.estimated_cost_usd = estimated_cost_usd


class AIPolicy:
    """Governance policy for AI engine usage."""
    def __init__(
        self,
        organization_id: str,
        allowed_providers: Optional[List[str]] = None,
        allowed_models: Optional[List[str]] = None,
        allow_external_ai: bool = False,
        privacy_mode: PrivacyMode = PrivacyMode.STRICT_LOCAL,
        max_risk_tolerance: str = "HIGH",
        require_human_approval: bool = True
    ):
        self.organization_id = organization_id
        self.allowed_providers = allowed_providers or ["local_default"]
        self.allowed_models = allowed_models or ["local-security-v1"]
        self.allow_external_ai = allow_external_ai
        self.privacy_mode = privacy_mode
        self.max_risk_tolerance = max_risk_tolerance
        self.require_human_approval = require_human_approval
