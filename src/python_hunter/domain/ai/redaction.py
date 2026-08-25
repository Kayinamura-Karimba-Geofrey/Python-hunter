"""Data Redaction and Sensitive Data Scrubber for AI Requests."""

import re
from typing import Dict, List, Tuple


class DataRedactor:
    """Scrubs secrets, credentials, API keys, private keys, tokens, and PII from prompts prior to external processing."""

    # Regex patterns for common sensitive credentials
    PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("AWS_KEY", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY-----.+?-----END (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY-----", re.DOTALL)),
        ("GENERIC_SECRET", re.compile(r"(?i)(?:secret|password|passwd|api_key|token|access_token|auth_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.\~]{8,})['\"]?")),
        ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}")),
        ("STRIPE_KEY", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
        ("GCP_KEY", re.compile(r"AIzaSy[0-9a-zA-Z_]{33}")),
        ("DATABASE_URL", re.compile(r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+")),
        ("BEARER_TOKEN", re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}")),
    ]

    def redact(self, text: str) -> str:
        """Redacts sensitive strings from the provided text."""
        if not text:
            return text

        redacted = text
        for label, pattern in self.PATTERNS:
            redacted = pattern.sub(f"[REDACTED_{label}]", redacted)

        return redacted
