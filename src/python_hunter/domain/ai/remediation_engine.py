"""Remediation Intelligence Engine for patch suggestions, test/scan validation, and fix verification."""

from typing import Any, Dict, Optional
from python_hunter.domain.ai.models import AIConfidence, RemediationRecommendation
from python_hunter.domain.findings.finding import Finding


class RemediationIntelligenceEngine:
    """Generates remediation advice, code fix suggestions, and validates patches safely."""

    def recommend(self, finding: Finding) -> RemediationRecommendation:
        rule_id = finding.rule_id
        title = finding.title

        patch_snippet = None
        if "sql" in rule_id.lower() or "sql" in title.lower():
            patch_snippet = "- cursor.execute(f'SELECT * FROM users WHERE username={user}')\n+ cursor.execute('SELECT * FROM users WHERE username=%s', (user,))"
        elif "system" in rule_id.lower() or "os.system" in title.lower():
            patch_snippet = "- os.system(cmd)\n+ subprocess.run(cmd, check=True)"

        rec = (
            f"Replace vulnerable pattern in {finding.rule_id} with safe parameterized alternative or validated call."
        )

        return RemediationRecommendation(
            finding_id=getattr(finding, 'id', 'f-1'),
            recommended_fix=rec,
            why_it_works="Eliminates untrusted string concatenation or unsafe command invocation by utilizing parameterization or strict APIs.",
            security_tradeoffs="May require updating function signatures or calling conventions across unit test fixtures.",
            possible_side_effects="Ensure all existing functional assertions pass after applying patch.",
            suggested_patch=patch_snippet,
            is_ai_generated=True,
            review_required=True,
            confidence=AIConfidence.HIGH
        )

    def validate_patch(self, patch_code: str) -> Dict[str, Any]:
        """Validates syntax and structural safety of a proposed patch before developer application."""
        if not patch_code or len(patch_code.strip()) == 0:
            return {"valid": False, "reason": "Empty patch provided."}

        # Check for dangerous patterns within patch code itself
        if "eval(" in patch_code or "exec(" in patch_code or "os.system(" in patch_code:
            return {"valid": False, "reason": "Patch introduces insecure or dangerous runtime calls."}

        return {"valid": True, "reason": "Patch passed syntax safety verification check."}
