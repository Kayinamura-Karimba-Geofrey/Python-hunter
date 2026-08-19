"""Repository Manager and Credentials implementation."""

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from python_hunter.infrastructure.repository.target_resolver import ScanTarget, TargetType

logger = logging.getLogger(__name__)


@dataclass
class RepositoryCredentials:
    """Manages GitHub tokens and SSH credentials safely without printing/logging sensitive tokens."""

    github_token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "RepositoryCredentials":
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        return cls(github_token=token)


class RepositoryManager:
    """Handles safe temporary cloning, checkout of branch/commit, and reliable cleanup on completion or interruption."""

    def __init__(self, credentials: Optional[RepositoryCredentials] = None) -> None:
        self.credentials = credentials or RepositoryCredentials.from_env()
        self.temp_dirs: list[str] = []

    def acquire_target(self, target: ScanTarget) -> str:
        """Ensures local availability of the scan target, cloning remote repos to an isolated temp directory."""
        if target.target_type in (TargetType.LOCAL_DIRECTORY, TargetType.LOCAL_FILE, TargetType.GIT_REPOSITORY):
            return target.local_path

        if target.target_type == TargetType.GITHUB_REPOSITORY:
            temp_dir = tempfile.mkdtemp(prefix="pyh_repo_")
            self.temp_dirs.append(temp_dir)

            clone_url = target.repository_url
            if self.credentials.github_token and "https://github.com/" in clone_url:
                clone_url = clone_url.replace(
                    "https://github.com/", f"https://x-access-token:{self.credentials.github_token}@github.com/"
                )

            cmd = ["git", "clone", "--depth", "1"]
            if target.branch:
                cmd.extend(["--branch", target.branch])
            cmd.extend([clone_url, temp_dir])

            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                self.cleanup()
                raise RuntimeError(f"Failed to clone remote repository '{target.source}' safely.") from e

            if target.commit:
                try:
                    subprocess.run(["git", "fetch", "--depth", "50"], cwd=temp_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["git", "checkout", target.commit], cwd=temp_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    self.cleanup()
                    raise RuntimeError(f"Failed to checkout commit '{target.commit}'.") from e

            return temp_dir

        raise ValueError(f"Unsupported target type: {target.target_type}")

    def cleanup(self) -> None:
        """Safely removes all temporary cloned repository directories."""
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        self.temp_dirs.clear()
