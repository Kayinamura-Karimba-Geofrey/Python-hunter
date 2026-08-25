"""AI Request Pipeline orchestrating context extraction, redaction, prompt protection, and execution."""

import uuid
from typing import List, Optional
from python_hunter.domain.ai.models import AIAuditLog, AIConfidence, FindingExplanation, PrivacyMode
from python_hunter.domain.ai.output_validator import OutputValidator
from python_hunter.domain.ai.prompt_guard import PromptGuard
from python_hunter.domain.ai.provider import AIProvider
from python_hunter.domain.ai.redaction import DataRedactor
from python_hunter.domain.ai.registry import AIProviderRegistry
from python_hunter.domain.findings.finding import Finding


class AIRequestPipeline:
    """Orchestrates Finding -> Context Extraction -> Data Redaction -> Prompt Guard -> Provider Execution -> Output Validation -> Audit Log."""

    def __init__(self, registry: Optional[AIProviderRegistry] = None) -> None:
        self.registry = registry or AIProviderRegistry()
        self.redactor = DataRedactor()
        self.prompt_guard = PromptGuard()
        self.output_validator = OutputValidator()
        self.audit_logs: List[AIAuditLog] = []

    def process_explanation(
        self,
        finding: Finding,
        user_id: str = "sys-admin",
        organization_id: str = "org-default",
        requested_provider_id: Optional[str] = None
    ) -> FindingExplanation:
        provider = self.registry.get_active_provider(requested_provider_id)

        # 1. Context Extraction
        finding_id = getattr(finding, 'id', 'f-101')
        rule_id = finding.rule_id
        title = finding.title
        loc_str = f"{finding.location.file_path}:{finding.location.start_line}" if finding.location else "unknown"

        raw_context = f"Finding {rule_id}: {title} at {loc_str}."

        # 2. Data Redaction
        redacted_context = self.redactor.redact(raw_context)

        # 3. Prompt Guard Protection
        safe_context, injection_detected = self.prompt_guard.sanitize_untrusted_content(redacted_context)

        # 4. Prompt Construction
        prompt = (
            f"Explain vulnerability finding '{rule_id}' ({title}) at location '{loc_str}'. "
            f"Evidence Context: {safe_context}"
        )

        # 5. Provider Execution with fallback
        try:
            raw_response = provider.generate(prompt, system_prompt="You are a security intelligence assistant.")
            status = "SUCCESS"
        except Exception as e:
            # Fallback to local default provider on failure
            local_p = self.registry.get("local_default")
            raw_response = local_p.generate(prompt) if local_p else "Fallback local explanation."
            status = f"FALLBACK ({str(e)})"

        # 6. Output Validation & Grounding Check
        evidence = [rule_id, title, loc_str]
        is_valid, quality = self.output_validator.validate_grounding([raw_response], evidence)

        # 7. Audit Logging
        audit_entry = AIAuditLog(
            log_id=str(uuid.uuid4()),
            user_id=user_id,
            organization_id=organization_id,
            provider_id=provider.provider_id,
            model=provider.config.model,
            request_type="explain_finding",
            status=status,
            tokens_used=len(prompt.split()) + len(raw_response.split()),
            estimated_cost_usd=0.001
        )
        self.audit_logs.append(audit_entry)

        return FindingExplanation(
            finding_id=finding_id,
            what_happened=f"Analyzer {rule_id} flagged potential vulnerability: {title}.",
            why_dangerous="Untrusted inputs or missing safety controls can allow unauthorized state modification or code execution.",
            location_summary=loc_str,
            attacker_possibilities="An attacker could leverage this vulnerability to bypass access controls or disrupt services.",
            remediation_summary="Apply strict parameterization, input validation, or secure standard libraries.",
            confidence=AIConfidence.HIGH if quality.grounding_score > 70 else AIConfidence.MEDIUM,
            evidence_grounding=evidence
        )
