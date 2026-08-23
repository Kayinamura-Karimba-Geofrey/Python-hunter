"""User, Session, API Token, and Password Security models."""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class UserStatus(str, Enum):
    """User account state."""

    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"


@dataclass
class User:
    """User representation in security platform."""

    user_id: str
    email: str
    display_name: str
    password_hash: str
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None

    @staticmethod
    def hash_password(password: str) -> str:
        """Secure PBKDF2 password hashing."""
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return f"{salt.hex()}:{pwd_hash.hex()}"

    def verify_password(self, password: str) -> bool:
        """Verify candidate password against PBKDF2 hash."""
        try:
            salt_hex, hash_hex = self.password_hash.split(":")
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)
            candidate_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
            return secrets.compare_digest(candidate_hash, expected_hash)
        except Exception:
            return False


@dataclass
class Session:
    """Authenticated Session record."""

    session_id: str
    user_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=24))
    revoked: bool = False

    @property
    def is_valid(self) -> bool:
        return not self.revoked and datetime.now(timezone.utc) < self.expires_at


@dataclass
class ApiToken:
    """Scoped API Token record."""

    token_id: str
    user_id: str
    name: str
    token_hash: str
    scopes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked: bool = False

    @staticmethod
    def generate_token_pair() -> tuple[str, str]:
        """Generate raw token string and its SHA-256 hash for storage."""
        raw_token = f"pyh_pat_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        return raw_token, token_hash
