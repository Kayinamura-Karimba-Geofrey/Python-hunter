"""Strong Centralized Secret Redaction Engine with Leak Prevention Guarantees."""

import re
from typing import Any, Dict, List, Optional


class Redactor:
    """Safe redactor sanitizing raw secrets from findings, snippets, logs, outputs, and exception traces."""

    @staticmethod
    def redact_value(secret_val: str, keep_prefix_len: int = 4, keep_suffix_len: int = 4) -> str:
        """Redact raw secret string while keeping minimal safe prefix/suffix if long enough."""
        if not secret_val:
            return "[REDACTED]"

        cleaned = secret_val.strip()
        length = len(cleaned)
        if length <= 8:
            return "[REDACTED]"

        if length <= keep_prefix_len + keep_suffix_len:
            prefix = cleaned[:2]
            suffix = cleaned[-2:]
            mask_len = length - 4
            return f"{prefix}{'*' * mask_len}{suffix}"

        prefix = cleaned[:keep_prefix_len]
        suffix = cleaned[-keep_suffix_len:]
        mask_len = length - (keep_prefix_len + keep_suffix_len)
        return f"{prefix}{'*' * mask_len}{suffix}"

    @classmethod
    def sanitize_evidence(cls, evidence_text: str, raw_secret: str) -> str:
        """Replace all occurrences of raw secret in evidence string with redacted representation."""
        if not evidence_text or not raw_secret:
            return evidence_text or ""

        redacted_preview = cls.redact_value(raw_secret)
        return evidence_text.replace(raw_secret, redacted_preview)

    @classmethod
    def sanitize_log_message(cls, message: str, known_secrets: Optional[List[str]] = None) -> str:
        """Sanitizes raw secrets from log messages and exception stack traces."""
        if not message:
            return ""

        sanitized = message
        if known_secrets:
            for s in known_secrets:
                if s and len(s) > 3:
                    sanitized = sanitized.replace(s, "[REDACTED_SECRET]")

        # Fallback regex sanitization for API keys, tokens, passwords in log strings
        patterns = [
            (r"(api[_-]?key\s*[:=]\s*)['\"]?([a-zA-Z0-9_\-]{8,})['\"]?", r"\1[REDACTED]"),
            (r"(password\s*[:=]\s*)['\"]?([^\s'\"]{4,})['\"]?", r"\1[REDACTED]"),
            (r"(token\s*[:=]\s*)['\"]?([a-zA-Z0-9_\-]{8,})['\"]?", r"\1[REDACTED]"),
            (r"(secret\s*[:=]\s*)['\"]?([a-zA-Z0-9_\-]{8,})['\"]?", r"\1[REDACTED]"),
        ]

        for pat, repl in patterns:
            sanitized = re.sub(pat, repl, sanitized, flags=re.IGNORECASE)

        return sanitized
