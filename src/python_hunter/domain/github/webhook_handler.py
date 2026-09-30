"""GitHub Webhook Handler with Signature Verification, Replay Protection & SSRF Defense."""

import hashlib
import hmac
import json
import logging
import os
import sys
from collections import OrderedDict
from urllib.parse import urlparse
from typing import Any, Dict, Optional

from python_hunter.domain.github.github_models import GitHubWebhookDelivery

logger = logging.getLogger("python_hunter.webhook")

ALLOWED_GITHUB_HOSTS = {"api.github.com", "github.com", "raw.githubusercontent.com"}
MAX_PAYLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB max payload size limit
MAX_TRACKED_DELIVERIES = 10_000  # Replay-cache bound (memory exhaustion defense)


class WebhookSecretNotConfiguredError(RuntimeError):
    """Raised when webhook signature verification is attempted without a configured secret."""

    pass


class WebhookValidationError(Exception):
    """Exception raised when webhook payload or signature is invalid."""
    pass


class GitHubWebhookHandler:
    """Validates and parses incoming GitHub webhooks safely."""

    def __init__(self, secret: Optional[str] = None) -> None:
        # V-01 fix: never fall back to a hardcoded secret. The secret must come from
        # configuration. When unset, signature verification hard-fails closed unless the
        # process is explicitly running in a development environment.
        env_secret = os.getenv("PYH_WEBHOOK_SECRET", "")
        resolved = secret or env_secret
        self._secret_configured = bool(resolved)
        if not resolved:
            is_dev = os.getenv("PYH_ENV", "production").lower() in ("dev", "development", "local", "test")
            if is_dev:
                resolved = f"pyh_dev_only_{os.urandom(16).hex()}"
                logger.warning(
                    "PYH_WEBHOOK_SECRET not set: using a random ephemeral secret for this "
                    "development session only. GitHub webhooks must be reconfigured accordingly."
                )
            else:
                # Constructible in production (so pure validation helpers like SSRF
                # checks keep working), but signature verification fails closed below.
                resolved = ""
        self.secret = resolved
        # V-13 fix: bounded FIFO replay cache instead of an unbounded dict.
        self._processed_deliveries: "OrderedDict[str, GitHubWebhookDelivery]" = OrderedDict()

    def validate_signature(self, raw_body: bytes, signature_header: Optional[str]) -> bool:
        """Validates GitHub HMAC SHA-256 signature (X-Hub-Signature-256)."""
        if not self._secret_configured:
            raise WebhookSecretNotConfiguredError(
                "Webhook secret is not configured. Set the PYH_WEBHOOK_SECRET environment "
                "variable to the GitHub webhook secret before processing deliveries."
            )
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
        while len(self._processed_deliveries) > MAX_TRACKED_DELIVERIES:
            self._processed_deliveries.popitem(last=False)
        return True

    @staticmethod
    def validate_ssrf_host(url: str) -> bool:
        """Validates that repository and external resource URLs belong to allowed GitHub hosts.

        V-03 hardening:
        - Only HTTPS is accepted for remote resources (plain HTTP is rejected).
        - The previous ``endswith(".github.com")`` check allowed lookalike domains
          (e.g. ``evil.github.com.attacker.io``); suffix matching now requires a dot
          boundary immediately after an allowed host.
        - Literal-IP URLs (http://169.254.169.254, http://127.0.0.1, ...) are rejected:
          they can never be legitimate GitHub hosts and enable cloud-metadata SSRF.
        """
        if not url:
            return True
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise WebhookValidationError(f"Invalid URL scheme: '{parsed.scheme}'. Only https:// is allowed.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise WebhookValidationError("SSRF violation: URL has no hostname.")

        # Reject literal-IP hosts entirely (metadata endpoints, loopback, link-local, RFC1918).
        try:
            import ipaddress

            ipaddress.ip_address(hostname)  # Raises ValueError if hostname is not an IP literal.
            raise WebhookValidationError(f"SSRF violation: Literal-IP URL '{hostname}' is not allowed.")
        except ValueError:
            pass

        allowed = hostname in ALLOWED_GITHUB_HOSTS or (
            "." in hostname and hostname.endswith(".github.com")
        )
        if not allowed:
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
