"""GitHub Webhook Handler with Signature Verification, Replay Protection & SSRF Defense."""

import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse
from typing import Any, Dict, Optional

from python_hunter.domain.github.github_models import GitHubWebhookDelivery

logger = logging.getLogger("python_hunter.webhook")

ALLOWED_GITHUB_HOSTS = {"api.github.com", "github.com", "raw.githubusercontent.com"}
MAX_PAYLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB max payload size limit


class WebhookValidationError(Exception):
    """Exception raised when webhook payload or signature is invalid."""
    pass


class GitHubWebhookHandler:
    """Validates and parses incoming GitHub webhooks safely."""

    def __init__(self, secret: Optional[str] = None) -> None:
        self.secret = secret or "pyh_webhook_secret_dev_12345"
        self._processed_deliveries: Dict[str, GitHubWebhookDelivery] = {}

    def validate_signature(self, raw_body: bytes, signature_header: Optional[str]) -> bool:
        """Validates GitHub HMAC SHA-256 signature (X-Hub-Signature-256)."""
        if not signature_header:
            raise WebhookValidationError("Missing X-Hub-Signature-256 header.")

        if not signature_header.startswith("sha256="):
            raise WebhookValidationError("Invalid signature header format. Must start with sha256=")

        expected_sig = signature_header.split("sha256=", 1)[1]
        mac = hmac.new(self.secret.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
        calculated_sig = mac.hexdigest()

        if not hmac.compare_digest(calculated_sig, expected_sig):
            raise WebhookValidationError("Invalid webhook signature. Request rejected.")
        return True

    def check_replay_and_record(self, delivery_id: Optional[str], event_type: str) -> bool:
        """Prevents replay attacks by verifying delivery ID (X-GitHub-Delivery)."""
        if not delivery_id:
            raise WebhookValidationError("Missing X-GitHub-Delivery header.")

        if delivery_id in self._processed_deliveries:
            logger.warning(f"Replay attack or duplicate delivery detected: {delivery_id}")
            return False  # Duplicate delivery, skip processing without error

        self._processed_deliveries[delivery_id] = GitHubWebhookDelivery(
            delivery_id=delivery_id,
            event_type=event_type,
        )
        return True

    @staticmethod
    def validate_ssrf_host(url: str) -> bool:
        """Validates that repository and external resource URLs belong to allowed GitHub hosts."""
        if not url:
            return True
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise WebhookValidationError(f"Invalid URL scheme: {parsed.scheme}")

        hostname = parsed.hostname or ""
        if hostname.lower() not in ALLOWED_GITHUB_HOSTS and not hostname.lower().endswith(".github.com"):
            raise WebhookValidationError(f"SSRF violation: Host '{hostname}' is not an allowed GitHub domain.")
        return True

    def parse_event(
        self,
        raw_body: bytes,
        signature_header: Optional[str],
        delivery_id: Optional[str],
        event_type: str,
    ) -> Dict[str, Any]:
        """Full security check & parse pipeline for incoming webhooks."""
        if len(raw_body) > MAX_PAYLOAD_SIZE_BYTES:
            raise WebhookValidationError("Webhook payload exceeds maximum size limit of 5MB.")

        # Signature validation
        self.validate_signature(raw_body, signature_header)

        # Replay protection check
        is_new = self.check_replay_and_record(delivery_id, event_type)
        if not is_new:
            return {"status": "DUPLICATE_DELIVERY", "message": "Delivery ID already processed."}

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            raise WebhookValidationError(f"Malformed JSON payload: {e}")

        # SSRF checks on repository clone URLs if present
        repo_info = payload.get("repository", {})
        if isinstance(repo_info, dict):
            clone_url = repo_info.get("clone_url") or repo_info.get("html_url")
            if clone_url:
                self.validate_ssrf_host(clone_url)

        return {
            "status": "ACCEPTED",
            "event_type": event_type,
            "delivery_id": delivery_id,
            "payload": payload,
        }
