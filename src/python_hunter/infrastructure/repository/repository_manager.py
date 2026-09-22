"""Repository Manager and Credentials implementation."""

import logging
import os
import shutil
import subprocess
import sys
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
            token = self.credentials.github_token or os.environ.get("GITHUB_TOKEN")
            if token and "https://github.com/" in clone_url:
                clone_url = clone_url.replace(
                    "https://github.com/", f"https://x-access-token:{token}@github.com/"
                )

            git_env = os.environ.copy()
            git_env["GIT_TERMINAL_PROMPT"] = "0"
            git_env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15"

            sys.stdout.write(f"[*] Acquiring remote repository: {target.source} ...\n")
            sys.stdout.flush()

            def build_clone_cmd(url: str) -> list[str]:
                c = ["git", "clone", "--depth", "1"]
                if target.branch:
                    if target.branch.startswith("-"):
                        raise ValueError(f"Potentially malicious git branch name detected: {target.branch}")
                    c.extend(["--branch", target.branch])
                c.extend(["--", url, temp_dir])
                return c

            cmd = build_clone_cmd(clone_url)
            try:
                clone_proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120, env=git_env, check=False
                )
            except subprocess.TimeoutExpired as e:
                self.cleanup()
                raise RuntimeError(f"Cloning '{target.source}' timed out after 120 seconds.") from e

            # If HTTPS clone failed (e.g. private repo authentication required) and no token was provided,
            # attempt fallback to SSH if the target is a GitHub repo.
            if clone_proc.returncode != 0 and clone_url.startswith("https://github.com/"):
                owner = target.metadata.get("owner")
                repo = target.metadata.get("repo")
                if owner and repo:
                    ssh_url = f"git@github.com:{owner}/{repo}.git"
                    sys.stdout.write(f"[*] HTTPS clone failed (private repository). Retrying via SSH: {ssh_url} ...\n")
                    sys.stdout.flush()
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    os.makedirs(temp_dir, exist_ok=True)
                    ssh_cmd = build_clone_cmd(ssh_url)
                    try:
                        ssh_proc = subprocess.run(
                            ssh_cmd, capture_output=True, text=True, timeout=120, env=git_env, check=False
                        )
                        if ssh_proc.returncode == 0:
                            clone_proc = ssh_proc
                        else:
                            clone_proc = ssh_proc
                    except subprocess.TimeoutExpired as e:
                        self.cleanup()
                        raise RuntimeError(f"SSH clone '{ssh_url}' timed out after 600 seconds.") from e

            if clone_proc.returncode != 0:
                self.cleanup()
                err_msg = clone_proc.stderr.strip() if clone_proc.stderr else f"Exit code {clone_proc.returncode}"
                raise RuntimeError(
                    f"Failed to clone remote repository '{target.source}' safely: {err_msg}\n"
                    f"Tip: For private repositories, configure GITHUB_TOKEN or use an SSH URL (git@github.com:...)."
                )

            if target.commit:
                if target.commit.startswith("-"):
                    raise ValueError(f"Potentially malicious git commit hash detected: {target.commit}")
                try:
                    subprocess.run(
                        ["git", "fetch", "--depth", "50"],
                        cwd=temp_dir,
                        check=True,
                        capture_output=True,
                        timeout=60,
                        env=git_env,
                    )
                    subprocess.run(
                        ["git", "checkout", "--", target.commit],
                        cwd=temp_dir,
                        check=True,
                        capture_output=True,
                        timeout=60,
                        env=git_env,
                    )
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
