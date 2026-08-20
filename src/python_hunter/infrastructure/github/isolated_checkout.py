"""Isolated Workspace Checkout Service for Safe Repository Scanning."""

import logging
import os
import shutil
import tempfile
from contextlib import contextmanager
from typing import Generator
from python_hunter.domain.github.webhook_handler import GitHubWebhookHandler

logger = logging.getLogger("python_hunter.checkout")


class IsolatedCheckoutService:
    """Manages temporary isolated workspaces for GitHub repository checkouts."""

    @contextmanager
    def create_isolated_workspace(self, repo_url: str, commit_sha: str) -> Generator[str, None, None]:
        """Creates an isolated temporary directory for repository checkout and guarantees cleanup on exit.
        
        Zero Code Execution Standard:
        - NEVER executes repository scripts, setup scripts, or workflow actions.
        - Strictly operates on raw file contents and static code parsing.
        """
        # Enforce SSRF validation on repository clone URL
        GitHubWebhookHandler.validate_ssrf_host(repo_url)

        temp_dir = tempfile.mkdtemp(prefix="pyh_checkout_")
        logger.info(f"Created isolated checkout workspace at {temp_dir} for SHA {commit_sha}")

        try:
            # Yield temporary workspace directory to the caller for static analysis
            yield temp_dir
        finally:
            # Mandatory cleanup of temporary files
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up isolated workspace at {temp_dir}")
                except Exception as e:
                    logger.error(f"Failed to cleanup temp workspace {temp_dir}: {e}")
