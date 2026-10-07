"""Authentication and scan-target validation for the REST API.

Tokens are HS256 JWTs signed with PYH_SECRET_KEY, and passwords are stored as PBKDF2-SHA256
hashes. Both use only the standard library.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from python_hunter.infrastructure.config.settings import Settings

_PBKDF2_ITERATIONS = 600_000
_ALGORITHM = "pbkdf2_sha256"


class AuthenticationError(Exception):
    """Raised when credentials or a bearer token are invalid."""


class TargetNotAllowedError(Exception):
    """Raised when a requested scan target lies outside the permitted workspace."""


def hash_password(password: str, iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Return a PBKDF2-SHA256 hash string suitable for PYH_API_PASSWORD_HASH."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGORITHM}${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != _ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _b64d(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, _b64d(expected))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenService:
    """Issues and verifies HS256 JWT bearer tokens."""

    def __init__(self, secret_key: str, ttl_minutes: int) -> None:
        if not secret_key:
            raise ValueError("A signing secret is required.")
        self._key = secret_key.encode("utf-8")
        self.ttl_seconds = ttl_minutes * 60

    def issue(self, subject: str, now: float | None = None) -> str:
        issued = int(now if now is not None else time.time())
        header = {"alg": "HS256", "typ": "JWT"}
        claims = {"sub": subject, "iat": issued, "exp": issued + self.ttl_seconds}
        signing_input = f"{_b64e(json.dumps(header).encode())}.{_b64e(json.dumps(claims).encode())}"
        return f"{signing_input}.{_b64e(self._sign(signing_input))}"

    def verify(self, token: str, now: float | None = None) -> dict[str, Any]:
        try:
            header_b64, claims_b64, sig_b64 = token.split(".")
            signing_input = f"{header_b64}.{claims_b64}"
            if not hmac.compare_digest(_b64d(sig_b64), self._sign(signing_input)):
                raise AuthenticationError("Invalid token signature.")
            header = json.loads(_b64d(header_b64))
            claims: dict[str, Any] = json.loads(_b64d(claims_b64))
        except AuthenticationError:
            raise
        except (ValueError, TypeError) as e:
            raise AuthenticationError("Malformed token.") from e
        if header.get("alg") != "HS256":
            raise AuthenticationError("Unsupported token algorithm.")
        if int(claims.get("exp", 0)) <= int(now if now is not None else time.time()):
            raise AuthenticationError("Token expired.")
        return claims

    def _sign(self, signing_input: str) -> bytes:
        return hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest()


class Authenticator:
    """Checks the configured API user's credentials and issues tokens."""

    def __init__(self, settings: Settings) -> None:
        self.username = settings.api.username
        self.password_hash = settings.api.password_hash
        # In development, an unset secret gets a per-process random key: tokens stop
        # working on restart, but nothing guessable is ever used to sign them.
        secret = settings.app.secret_key or secrets.token_urlsafe(48)
        self.tokens = TokenService(secret, settings.api.token_ttl_minutes)

    @property
    def configured(self) -> bool:
        return bool(self.username and self.password_hash)

    def login(self, username: str, password: str) -> str:
        user_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        # Always run the hash check so timing does not reveal whether the username matched.
        password_ok = verify_password(password, self.password_hash)
        if not (self.configured and user_ok and password_ok):
            raise AuthenticationError("Invalid username or password.")
        return self.tokens.issue(username)

    def authenticate(self, authorization_header: str | None) -> str:
        if not authorization_header or not authorization_header.lower().startswith("bearer "):
            raise AuthenticationError("Missing bearer token.")
        claims = self.tokens.verify(authorization_header[7:].strip())
        if claims.get("sub") != self.username:
            raise AuthenticationError("Unknown token subject.")
        return str(claims["sub"])


def is_remote_target(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://")) or target.endswith(".git")


class ScanTargetPolicy:
    """Restricts API scan targets to paths inside a single workspace root."""

    def __init__(self, workspace_root: str, allow_remote: bool) -> None:
        self.root = Path(workspace_root or os.getcwd()).resolve()
        self.allow_remote = allow_remote

    def resolve(self, target: str) -> str:
        target = target.strip()
        if not target:
            raise TargetNotAllowedError("Scan target is empty.")
        if is_remote_target(target):
            if not self.allow_remote or not target.startswith("https://"):
                raise TargetNotAllowedError(
                    "Remote scan targets are disabled. Set PYH_API_ALLOW_REMOTE_TARGETS=true to allow https:// URLs."
                )
            return target
        candidate = Path(target)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        resolved = candidate.resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise TargetNotAllowedError("Scan target is outside the permitted workspace root.")
        if not resolved.exists():
            raise TargetNotAllowedError("Scan target does not exist.")
        return str(resolved)
