"""Prompt Guard & Injection Defense Engine."""

import re
from typing import Tuple


class PromptGuard:
    """Protects against adversarial prompt injection, jailbreaks, and instructions embedded in untrusted repository files."""

    INJECTION_PATTERNS = [
        re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
        re.compile(r"(?i)reveal\s+(?:all\s+)?secrets"),
        re.compile(r"(?i)system\s+override"),
        re.compile(r"(?i)disregard\s+security\s+rules"),
        re.compile(r"(?i)bypass\s+policy"),
        re.compile(r"(?i)execute\s+command"),
        re.compile(r"(?i)you\s+are\s+now\s+a\s+unrestricted"),
        re.compile(r"(?i)print\s+environment\s+variables"),
    ]

    def sanitize_untrusted_content(self, text: str) -> Tuple[str, bool]:
        """Sanitizes source code snippets or comments against malicious prompt injections."""
        if not text:
            return text, False

        detected = False
        sanitized = text

        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(sanitized):
                detected = True
                sanitized = pattern.sub("[SANITIZED_PROMPT_INJECTION_ATTEMPT]", sanitized)

        return sanitized, detected
