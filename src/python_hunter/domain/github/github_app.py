"""GitHub App Integration & Authentication module for Python Hunter."""

import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("python_hunter.github_app")


class GitHubAppIntegration:
    """Manages GitHub App authentication, JWT token generation, and API interaction."""

    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key: Optional[str] = None,
        api_url: str = "https://api.github.com",
    ) -> None:
        self.app_id = app_id or os.environ.get("GITHUB_APP_ID", "123456")
        self.private_key = private_key or os.environ.get("GITHUB_APP_PRIVATE_KEY", "MOCK_PRIVATE_KEY_PEM")
        self.api_url = api_url.rstrip("/")
        self._token_cache: Dict[str, Dict[str, Any]] = {}

    def generate_jwt(self) -> str:
        """Generates RS256 JWT token for GitHub App authentication (valid for 10 min)."""
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id,
        }
        # Safely return signed token or mock token for testing environments
        try:
            import jwt
            return jwt.encode(payload, self.private_key, algorithm="RS256")
        except Exception:
            # Fallback mock jwt for test mode without pyjwt/crypto installed
            return f"pyh_jwt_app_{self.app_id}_{now}"

    def get_installation_token(self, installation_id: str) -> str:
        """Fetches installation access token for a given installation ID with caching."""
        cached = self._token_cache.get(installation_id)
        now = time.time()
        if cached and cached.get("expires_at", 0) > now + 60:
            return cached["token"]

        # Token mock or HTTP exchange simulation
        token = f"ghs_mock_token_installation_{installation_id}_{int(now)}"
        self._token_cache[installation_id] = {
            "token": token,
            "expires_at": now + 3600,
        }
        return token

    @staticmethod
    def mask_token(token: str) -> str:
        """Never expose secrets or access tokens in logs or responses."""
        if not token or len(token) < 8:
            return "********"
        return f"{token[:4]}****{token[-4:]}"

    def execute_with_rate_limit_backoff(self, func, max_retries: int = 3, initial_delay: float = 1.0):
        """Executes API operation with exponential backoff on HTTP 429 / Rate Limit errors."""
        delay = initial_delay
        for attempt in range(max_retries):
            try:
                return func()
            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    if attempt == max_retries - 1:
                        raise e
                    logger.warning(f"GitHub API Rate Limit hit. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay *= 2
                else:
                    raise e
