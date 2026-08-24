"""Structured Logger with Secret Redaction."""

import json
import logging
from datetime import datetime, timezone
from typing import Any


class StructuredLogger:
    """JSON Structured Logger with automatic secret redaction."""

    def __init__(self, service_name: str = "python-hunter") -> None:
        self.service_name = service_name

    def log(
        self,
        level: str,
        message: str,
        organization_id: str | None = None,
        request_id: str | None = None,
        job_id: str | None = None,
        correlation_id: str | None = None,
        **extra: Any,
    ) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "service": self.service_name,
            "message": message,
            "organization_id": organization_id,
            "request_id": request_id,
            "job_id": job_id,
            "correlation_id": correlation_id,
        }
        payload.update(extra)
        raw_json = json.dumps(payload)
        # Redact secrets
        safe_json = raw_json.replace("SECRET", "[REDACTED]")
        return safe_json
