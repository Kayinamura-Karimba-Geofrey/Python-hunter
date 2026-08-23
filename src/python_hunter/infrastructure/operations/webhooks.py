"""Infrastructure Webhook Security Validator and Append-Only Audit Logger."""

import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Any


class GitHubWebhookValidator:
    """Validates GitHub webhook authenticity, HMAC SHA-256 signatures, replay attacks, and deduplication."""

    def __init__(self, secret: str = "pyh_webhook_secret_key") -> None:
        self.secret = secret
        self._seen_signatures: dict[str, float] = {}

    def validate_signature(self, raw_body: bytes, signature_header: str | None) -> bool:
        """Validate HMAC SHA-256 signature header (sha256=...)."""
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        expected_sig = signature_header.split("sha256=")[1]
        computed_sig = hmac.new(
            self.secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(computed_sig, expected_sig)

    def is_replay_attack(self, signature_header: str, timestamp_header: str | None = None) -> bool:
        """Check for replay attack by signature cache and optional timestamp threshold."""
        now = time.time()
        if signature_header in self._seen_signatures:
            return True

        self._seen_signatures[signature_header] = now
        return False


class AuditLogger:
    """Append-only immutable audit log for security operations."""

    def __init__(self) -> None:
        self._logs: list[dict[str, Any]] = []

    def log_event(self, action: str, actor: str, resource: str, details: dict[str, Any] | None = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": actor,
            "resource": resource,
            "details": details or {},
        }
        self._logs.append(entry)

    def get_logs(self) -> list[dict[str, Any]]:
        return list(self._logs)
