"""Configuration Manager and Environment Validation."""

import os
from dataclasses import dataclass
from enum import Enum


class EnvironmentType(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class Configuration:
    """Central configuration container."""

    environment: EnvironmentType = EnvironmentType.DEVELOPMENT
    master_key: str = "pyh_enterprise_master_key_32bytes"
    db_connection_pool_size: int = 20
    cache_ttl_seconds: int = 300


class ConfigurationManager:
    """Configuration loader & validator."""

    def load_configuration(self) -> Configuration:
        env_str = os.getenv("PYH_ENV", "development").lower()
        try:
            env = EnvironmentType(env_str)
        except ValueError:
            env = EnvironmentType.DEVELOPMENT

        return Configuration(
            environment=env,
            master_key=os.getenv("PYH_MASTER_KEY", "pyh_enterprise_master_key_32bytes"),
        )
