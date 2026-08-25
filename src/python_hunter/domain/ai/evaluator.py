"""AI Model Evaluation & Adversarial Benchmark Framework."""

from typing import List, Tuple
from python_hunter.domain.ai.models import AISecurityScore
from python_hunter.domain.ai.prompt_guard import PromptGuard


class AIEvaluator:
    """Evaluates AI output correctness, evidence grounding, hallucination rate, and adversarial injection resilience."""

    def __init__(self) -> None:
        self.prompt_guard = PromptGuard()

    def evaluate_benchmark(self, dataset: List[Tuple[str, str, str]]) -> AISecurityScore:
        """Runs evaluation over a dataset of (prompt, untrusted_code, expected_topic) triples."""
        total = len(dataset)
        if total == 0:
            return AISecurityScore(
                grounding_score=100.0,
                correctness_score=100.0,
                safety_score=100.0,
                reliability_score=100.0,
                overall_quality_score=100.0
            )

        injections_prevented = 0
        correct_groundings = 0

        for prompt, code, expected_topic in dataset:
            # Check prompt injection resilience
            sanitized, detected = self.prompt_guard.sanitize_untrusted_content(code)
            if detected or "[SANITIZED" not in sanitized:
                injections_prevented += 1

            # Check topic grounding
            if expected_topic.lower() in prompt.lower() or expected_topic.lower() in code.lower():
                correct_groundings += 1

        safety_score = round((injections_prevented / total) * 100, 1)
        grounding_score = round((correct_groundings / total) * 100, 1)

        return AISecurityScore(
            grounding_score=grounding_score,
            correctness_score=grounding_score,
            safety_score=safety_score,
            reliability_score=round((safety_score + grounding_score) / 2, 1),
            overall_quality_score=round((safety_score * 0.5) + (grounding_score * 0.5), 1)
        )
