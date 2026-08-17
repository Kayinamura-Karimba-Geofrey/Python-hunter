"""Strong Secret Redaction Engine."""

import re


class Redactor:
    """Safe redactor sanitizing raw secrets from findings, snippets, logs, and outputs."""

    @staticmethod
    def redact_value(secret_val: str, keep_prefix_len: int = 4, keep_suffix_len: int = 4) -> str:
        """Redact raw secret string while keeping minimal safe prefix/suffix if long enough."""
        if not secret_val:
            return "[REDACTED]"

        length = len(secret_val)
        if length <= 8:
            return "[REDACTED]"

        if length <= keep_prefix_len + keep_suffix_len:
            prefix = secret_val[:2]
            suffix = secret_val[-2:]
            mask_len = length - 4
            return f"{prefix}{'*' * mask_len}{suffix}"

        prefix = secret_val[:keep_prefix_len]
        suffix = secret_val[-keep_suffix_len:]
        mask_len = length - (keep_prefix_len + keep_suffix_len)
        return f"{prefix}{'*' * mask_len}{suffix}"

    @classmethod
    def sanitize_evidence(cls, evidence_text: str, raw_secret: str) -> str:
        """Replace all occurrences of raw secret in evidence string with redacted representation."""
        if not evidence_text or not raw_secret:
            return evidence_text or ""

        redacted_preview = cls.redact_value(raw_secret)
        return evidence_text.replace(raw_secret, redacted_preview)
