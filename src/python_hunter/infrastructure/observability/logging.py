"""Structured Logging Infrastructure."""

from datetime import datetime, timezone
import json
import re
import sys
from typing import Any

# Sensitive pattern definitions for secret masking
SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|password|token|auth|bearer)\s*[:=]\s*['\"]?([^'\"\s]+)['\"]?", re.IGNORECASE),
]


def redact_secrets(text: str) -> str:
    """Mask sensitive key/value pairs in log messages."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(r"\1: [REDACTED]", redacted)
    return redacted


class Logger:
    """Structured Logger implementation."""

    def __init__(self, name: str, level: str = "INFO", format_type: str = "text") -> None:
        self.name = name
        self.level_name = level.upper()
        self.format_type = format_type
        self._levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
        self.current_level = self._levels.get(self.level_name, 20)

    def _log(self, level: str, event: str, **kwargs: Any) -> None:
        if self._levels.get(level, 0) < self.current_level:
            return

        timestamp = datetime.now(timezone.utc).isoformat()
        clean_event = redact_secrets(event)
        clean_kwargs = {k: redact_secrets(str(v)) if isinstance(v, str) else v for k, v in kwargs.items()}

        if self.format_type == "json":
            payload = {
                "timestamp": timestamp,
                "level": level,
                "logger": self.name,
                "event": clean_event,
                **clean_kwargs,
            }
            sys.stdout.write(json.dumps(payload) + "\n")
        else:
            kw_str = " ".join(f"{k}={v}" for k, v in clean_kwargs.items())
            msg = f"[{timestamp}] [{level}] [{self.name}] {clean_event}"
            if kw_str:
                msg += f" | {kw_str}"
            sys.stdout.write(msg + "\n")
        sys.stdout.flush()

    def debug(self, event: str, **kwargs: Any) -> None:
        self._log("DEBUG", event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log("INFO", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log("WARNING", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._log("ERROR", event, **kwargs)

    def critical(self, event: str, **kwargs: Any) -> None:
        self._log("CRITICAL", event, **kwargs)


def get_logger(name: str, level: str = "INFO", format_type: str = "text") -> Logger:
    """Factory helper to obtain a named Logger instance."""
    return Logger(name=name, level=level, format_type=format_type)
