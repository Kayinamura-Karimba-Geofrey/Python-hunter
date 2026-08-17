"""Centralized Configuration System."""

from dataclasses import dataclass, field
import os
from typing import Any
from python_hunter.domain.exceptions.base import ConfigurationError


@dataclass
class AppConfig:
    """General Application Settings."""

    env: str = "development"
    debug: bool = True
    secret_key: str = "change-this-in-production-super-secret-key"


@dataclass
class LogConfig:
    """Logging Settings."""

    level: str = "INFO"
    format: str = "text"  # "text" or "json"
    redact_secrets: bool = True

    def __post_init__(self) -> None:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid log level '{self.level}'. Must be one of {valid_levels}",
                {"level": self.level},
            )


@dataclass
class ScanConfig:
    """Scanning Engine Limits and Settings."""

    max_file_size_mb: int = 10
    timeout_seconds: int = 300
    max_archive_ratio: int = 10
    min_severity: str = "LOW"

    def __post_init__(self) -> None:
        if self.max_file_size_mb <= 0:
            raise ConfigurationError("max_file_size_mb must be > 0", {"val": self.max_file_size_mb})
        if self.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be > 0", {"val": self.timeout_seconds})


@dataclass
class Settings:
    """Master Application Settings Root."""

    app: AppConfig = field(default_factory=AppConfig)
    log: LogConfig = field(default_factory=LogConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)

    @classmethod
    def load_from_env(cls, env_override: dict[str, str] | None = None) -> "Settings":
        """Load settings from environment variables prefixed with PYH_."""
        env = env_override if env_override is not None else os.environ

        app_env = env.get("PYH_ENV", "development")
        app_debug = env.get("PYH_DEBUG", "true").lower() in ("true", "1", "yes")
        app_secret = env.get("PYH_SECRET_KEY", "change-this-in-production-super-secret-key")

        log_level = env.get("PYH_LOG_LEVEL", "INFO")
        log_format = env.get("PYH_LOG_FORMAT", "text")

        try:
            max_size = int(env.get("PYH_MAX_SCAN_FILE_SIZE_MB", "10"))
            timeout = int(env.get("PYH_SCAN_TIMEOUT_SECONDS", "300"))
        except ValueError as e:
            raise ConfigurationError(f"Failed to parse numeric setting from environment: {e}") from e

        min_sev = env.get("PYH_MIN_SEVERITY", "LOW")

        return cls(
            app=AppConfig(env=app_env, debug=app_debug, secret_key=app_secret),
            log=LogConfig(level=log_level, format=log_format),
            scan=ScanConfig(
                max_file_size_mb=max_size,
                timeout_seconds=timeout,
                min_severity=min_sev,
            ),
        )
