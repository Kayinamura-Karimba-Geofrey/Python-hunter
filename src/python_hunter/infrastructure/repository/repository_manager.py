"""Repository Manager and Credentials implementation."""

import logging
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
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


def _kill_proc(proc: subprocess.Popen[bytes]) -> None:
    """Safely terminate and reap a subprocess."""
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass


def _run_git_with_watchdog(
    cmd: list[str],
    env: dict[str, str],
    timeout: Optional[int] = None,
    idle_timeout: Optional[int] = None,
    show_progress: bool = True,
    target_name: str = "remote repository",
) -> subprocess.CompletedProcess[str]:
    """Executes a Git command with an activity/progress-aware watchdog.

    Args:
        cmd: The command arguments.
        env: Environment variables.
        timeout: Maximum total wall-clock seconds allowed. 0 or None disables wall-clock limit.
        idle_timeout: Maximum seconds of zero output/activity before aborting. Defaults to 45s.
        show_progress: If True, streams progress updates to sys.stderr.
        target_name: Human-friendly name of target for error messages.
    """
    if idle_timeout is None:
        env_idle = os.getenv("GIT_CLONE_IDLE_TIMEOUT")
        idle_timeout = int(env_idle) if env_idle and env_idle.isdigit() else 45

    if timeout is None:
        env_timeout = os.getenv("GIT_CLONE_TIMEOUT")
        timeout = int(env_timeout) if env_timeout and env_timeout.isdigit() else 0

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        bufsize=0,
    )

    sel = selectors.DefaultSelector()
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ, data="stdout")
    if proc.stderr:
        sel.register(proc.stderr, selectors.EVENT_READ, data="stderr")

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    start_time = time.time()
    last_activity_time = time.time()

    try:
        while sel.get_map():
            now = time.time()

            # 1. Wall-clock timeout check (if configured and > 0)
            if timeout and timeout > 0:
                total_elapsed = now - start_time
                if total_elapsed >= timeout:
                    _kill_proc(proc)
                    raise RuntimeError(
                        f"Cloning '{target_name}' exceeded maximum wall-clock timeout of {timeout} seconds."
                    )
                sel_wait = min(1.0, max(0.05, timeout - total_elapsed))
            else:
                sel_wait = 1.0

            # 2. Inactivity / stall watchdog check
            if idle_timeout and idle_timeout > 0:
                idle_elapsed = now - last_activity_time
                if idle_elapsed >= idle_timeout:
                    _kill_proc(proc)
                    raise RuntimeError(
                        f"Cloning '{target_name}' stalled: no data or progress received for {idle_timeout} seconds."
                    )
                sel_wait = min(sel_wait, max(0.05, idle_timeout - idle_elapsed))

            events = sel.select(timeout=sel_wait)
            if not events:
                continue

            for key, _ in events:
                stream = key.fileobj
                data_type = key.data
                try:
                    chunk = os.read(stream.fileno(), 8192)
                except (OSError, ValueError):
                    chunk = b""

                if chunk:
                    last_activity_time = time.time()
                    if data_type == "stdout":
                        stdout_chunks.append(chunk)
                    else:
                        stderr_chunks.append(chunk)
                        if show_progress:
                            try:
                                text = chunk.decode("utf-8", errors="replace")
                                sys.stderr.write(text)
                                sys.stderr.flush()
                            except Exception:
                                pass
                else:
                    try:
                        sel.unregister(stream)
                        stream.close()
                    except Exception:
                        pass

        proc.wait()
        if show_progress and stderr_chunks:
            sys.stderr.write("\n")
            sys.stderr.flush()

        stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode if proc.returncode is not None else 0,
            stdout=stdout_str,
            stderr=stderr_str,
        )
    except Exception:
        _kill_proc(proc)
        raise
    finally:
        try:
            sel.close()
        except Exception:
            pass
        if proc.stdout and not proc.stdout.closed:
            try:
                proc.stdout.close()
            except Exception:
                pass
        if proc.stderr and not proc.stderr.closed:
            try:
                proc.stderr.close()
            except Exception:
                pass


class RepositoryManager:
    """Handles safe temporary cloning, checkout of branch/commit, and reliable cleanup on completion or interruption."""

    def __init__(
        self,
        credentials: Optional[RepositoryCredentials] = None,
        timeout: Optional[int] = None,
        idle_timeout: Optional[int] = None,
    ) -> None:
        self.credentials = credentials or RepositoryCredentials.from_env()
        self.temp_dirs: list[str] = []
        self.default_timeout = timeout
        self.default_idle_timeout = idle_timeout

    def acquire_target(
        self,
        target: ScanTarget,
        dest_dir: Optional[str] = None,
        timeout: Optional[int] = None,
        idle_timeout: Optional[int] = None,
        show_progress: bool = True,
    ) -> str:
        """Ensures local availability of the scan target, cloning remote repos to an isolated temp or specified destination directory."""
        if target.target_type in (TargetType.LOCAL_DIRECTORY, TargetType.LOCAL_FILE, TargetType.GIT_REPOSITORY):
            return target.local_path

        if target.target_type == TargetType.GITHUB_REPOSITORY:
            target_dir = dest_dir
            if not target_dir:
                target_dir = tempfile.mkdtemp(prefix="pyh_repo_")
                self.temp_dirs.append(target_dir)

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

            eff_timeout = timeout if timeout is not None else self.default_timeout
            eff_idle = idle_timeout if idle_timeout is not None else self.default_idle_timeout

            def build_clone_cmd(url: str) -> list[str]:
                c = ["git", "clone", "--depth", "1", "--single-branch", "--progress"]
                if target.branch:
                    if target.branch.startswith("-"):
                        raise ValueError(f"Potentially malicious git branch name detected: {target.branch}")
                    c.extend(["--branch", target.branch])
                c.extend(["--", url, target_dir])
                return c

            cmd = build_clone_cmd(clone_url)
            try:
                clone_proc = _run_git_with_watchdog(
                    cmd,
                    env=git_env,
                    timeout=eff_timeout,
                    idle_timeout=eff_idle,
                    show_progress=show_progress,
                    target_name=target.source,
                )
            except Exception:
                self.cleanup()
                raise

            # If HTTPS clone failed (e.g. private repo authentication required) and no token was provided,
            # attempt fallback to SSH if the target is a GitHub repo.
            if clone_proc.returncode != 0 and clone_url.startswith("https://github.com/"):
                owner = target.metadata.get("owner")
                repo = target.metadata.get("repo")
                if owner and repo:
                    ssh_url = f"git@github.com:{owner}/{repo}.git"
                    sys.stdout.write(f"[*] HTTPS clone failed (private repository). Retrying via SSH: {ssh_url} ...\n")
                    sys.stdout.flush()
                    if os.path.exists(target_dir):
                        shutil.rmtree(target_dir, ignore_errors=True)
                    os.makedirs(target_dir, exist_ok=True)
                    ssh_cmd = build_clone_cmd(ssh_url)
                    try:
                        ssh_proc = _run_git_with_watchdog(
                            ssh_cmd,
                            env=git_env,
                            timeout=eff_timeout,
                            idle_timeout=eff_idle,
                            show_progress=show_progress,
                            target_name=ssh_url,
                        )
                        clone_proc = ssh_proc
                    except Exception:
                        self.cleanup()
                        raise

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
                        cwd=target_dir,
                        check=True,
                        capture_output=True,
                        timeout=60,
                        env=git_env,
                    )
                    subprocess.run(
                        ["git", "checkout", "--", target.commit],
                        cwd=target_dir,
                        check=True,
                        capture_output=True,
                        timeout=60,
                        env=git_env,
                    )
                except Exception as e:
                    self.cleanup()
                    raise RuntimeError(f"Failed to checkout commit '{target.commit}'.") from e

            return target_dir

        raise ValueError(f"Unsupported target type: {target.target_type}")

    def cleanup(self) -> None:
        """Safely removes all temporary cloned repository directories."""
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        self.temp_dirs.clear()

