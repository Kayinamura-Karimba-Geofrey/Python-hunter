"""Output Validator and Hallucination Detector."""

from typing import List, Tuple
from python_hunter.domain.ai.models import AISecurityScore


class OutputValidator:
    """Validates AI outputs against deterministic evidence to catch hallucinations and unsupported claims."""

    def validate_grounding(
        self,
        ai_claims: List[str],
        known_evidence: List[str]
    ) -> Tuple[bool, AISecurityScore]:
        """Compares AI generated claims against actual deterministic evidence."""
        if not ai_claims:
            score = AISecurityScore(
                grounding_score=100.0,
                correctness_score=100.0,
                safety_score=100.0,
                reliability_score=100.0,
                overall_quality_score=100.0
            )
            return True, score

        grounded_count = 0
        evidence_lower = [e.lower() for e in known_evidence]

        for claim in ai_claims:
            claim_l = claim.lower()
            # Verify if claim shares tokens or keywords with known scanner evidence
            if any(ev_token in claim_l for ev in evidence_lower for ev_token in ev.split()):
                grounded_count += 1

        grounding_ratio = grounded_count / len(ai_claims) if ai_claims else 1.0
        grounding_score = round(grounding_ratio * 100, 1)

        is_valid = grounding_score >= 50.0

        score = AISecurityScore(
            grounding_score=grounding_score,
            correctness_score=grounding_score,
            safety_score=95.0,
            reliability_score=grounding_score,
            overall_quality_score=round((grounding_score * 0.7) + (95.0 * 0.3), 1)
        )

        return is_valid, score
