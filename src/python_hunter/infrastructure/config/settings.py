"""Centralized Configuration System."""

import os
from dataclasses import dataclass, field

from python_hunter.domain.exceptions.base import ConfigurationError


@dataclass
class AppConfig:
    """General Application Settings."""

    env: str = "development"
    debug: bool = True
    secret_key: str = ""

    # V-02 fix: known-insecure default keys. Starting a production process with one of
    # these (or an empty key) is a critical misconfiguration, so it is rejected.
    FORBIDDEN_SECRET_KEYS = {
        "",
        "change-this-in-production-super-secret-key",
        "change-this-in-production-super-secret-key-32-chars",
    }

    def __post_init__(self) -> None:
        if self.env.lower() not in ("development", "dev", "local", "test") and self.secret_key in self.FORBIDDEN_SECRET_KEYS:
            raise ConfigurationError(
                "Refusing to start in production with the default PYH_SECRET_KEY. "
                "Generate a unique high-entropy secret, e.g.: python -c "
                "'import secrets; print(secrets.token_urlsafe(48))'",
                {"env": self.env},
            )

    def is_development(self) -> bool:
        return self.env.lower() in ("development", "dev", "local", "test")


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


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class ApiConfig:
    """REST API authentication, CORS, and scan-target settings."""

    username: str = ""
    # PBKDF2 hash produced by python_hunter.application.api.security.hash_password
    password_hash: str = ""
    token_ttl_minutes: int = 60
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173"])
    workspace_root: str = ""
    allow_remote_targets: bool = False
    max_concurrent_scans: int = 2

    def __post_init__(self) -> None:
        if self.token_ttl_minutes <= 0:
            raise ConfigurationError("token_ttl_minutes must be > 0", {"val": self.token_ttl_minutes})
        if self.max_concurrent_scans <= 0:
            raise ConfigurationError("max_concurrent_scans must be > 0", {"val": self.max_concurrent_scans})
        if "*" in self.cors_origins:
            raise ConfigurationError(
                "Wildcard CORS origin is not allowed; list explicit origins in PYH_API_CORS_ORIGINS.",
                {"cors_origins": self.cors_origins},
            )

    @property
    def auth_configured(self) -> bool:
        return bool(self.username and self.password_hash)


@dataclass
class Settings:
    """Master Application Settings Root."""

    app: AppConfig = field(default_factory=AppConfig)
    log: LogConfig = field(default_factory=LogConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    api: ApiConfig = field(default_factory=ApiConfig)

    @classmethod
    def load_from_env(cls, env_override: dict[str, str] | None = None) -> "Settings":
        """Load settings from environment variables prefixed with PYH_."""
        env = env_override if env_override is not None else os.environ

        app_env = env.get("PYH_ENV", "development")
        app_debug = env.get("PYH_DEBUG", "true").lower() in ("true", "1", "yes")
        # V-02 fix: no default secret key is invented here. Production startup with a
        # missing/default key is rejected by AppConfig.__post_init__ below.
        app_secret = env.get("PYH_SECRET_KEY", "")

        log_level = env.get("PYH_LOG_LEVEL", "INFO")
        log_format = env.get("PYH_LOG_FORMAT", "text")

        try:
            max_size = int(env.get("PYH_MAX_SCAN_FILE_SIZE_MB", "10"))
            timeout = int(env.get("PYH_SCAN_TIMEOUT_SECONDS", "300"))
            token_ttl = int(env.get("PYH_API_TOKEN_TTL_MINUTES", "60"))
            max_scans = int(env.get("PYH_API_MAX_CONCURRENT_SCANS", "2"))
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
            api=ApiConfig(
                username=env.get("PYH_API_USERNAME", ""),
                password_hash=env.get("PYH_API_PASSWORD_HASH", ""),
                token_ttl_minutes=token_ttl,
                cors_origins=_split_csv(env.get("PYH_API_CORS_ORIGINS", "http://localhost:5173")),
                workspace_root=env.get("PYH_API_WORKSPACE_ROOT", ""),
                allow_remote_targets=env.get("PYH_API_ALLOW_REMOTE_TARGETS", "false").lower() in ("true", "1", "yes"),
                max_concurrent_scans=max_scans,
            ),
        )
