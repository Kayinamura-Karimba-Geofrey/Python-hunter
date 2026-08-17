"""Subprocess-Based Read-Only Git Repository Implementation."""

import os
import re
import subprocess
from typing import Any

from python_hunter.domain.git.interfaces import GitRepository
from python_hunter.domain.git.models import (
    ChangeType,
    GitCommit,
    GitFileChange,
    GitHookInfo,
    GitRemoteInfo,
    GitRepositoryMetadata,
    HistoryCompleteness,
)


class SubprocessGitRepository(GitRepository):
    """Production implementation of GitRepository using safe subprocess argument arrays.
    
    GUARANTEE: Strictly read-only operations. Never executes mutating Git commands.
    """

    def __init__(self, target_path: str, timeout_seconds: int = 15) -> None:
        self.target_path = os.path.abspath(target_path)
        self.timeout_seconds = timeout_seconds
        self._repo_root: str | None = None
        self._is_git: bool | None = None

    def is_valid_repository(self) -> bool:
        if self._is_git is not None:
            return self._is_git
        root = self.get_repository_root()
        self._is_git = bool(root and os.path.exists(os.path.join(root, ".git")))
        return self._is_git

    def get_repository_root(self) -> str:
        if self._repo_root is not None:
            return self._repo_root

        # Try git rev-parse first
        output = self._run_git(["rev-parse", "--show-toplevel"], cwd=self.target_path)
        if output:
            self._repo_root = output.strip()
            return self._repo_root

        # Fallback: Walk parent directories checking for .git
        curr = self.target_path
        if os.path.isfile(curr):
            curr = os.path.dirname(curr)

        while curr and curr != os.path.dirname(curr):
            if os.path.exists(os.path.join(curr, ".git")):
                self._repo_root = curr
                return self._repo_root
            curr = os.path.dirname(curr)

        self._repo_root = ""
        return ""

    def get_metadata(self) -> GitRepositoryMetadata:
        root = self.get_repository_root()
        if not root or not self.is_valid_repository():
            return GitRepositoryMetadata(repository_root=self.target_path, completeness=HistoryCompleteness.UNKNOWN)

        head_hash = self._run_git(["rev-parse", "HEAD"], cwd=root) or ""
        head_hash = head_hash.strip()

        # Branches
        branches_raw = self._run_git(["branch", "--list"], cwd=root) or ""
        branches = [b.strip("* ").strip() for b in branches_raw.splitlines() if b.strip()]

        # Tags
        tags_raw = self._run_git(["tag", "--list"], cwd=root) or ""
        tags = [t.strip() for t in tags_raw.splitlines() if t.strip()]

        # Shallow check
        git_dir = os.path.join(root, ".git")
        is_shallow = os.path.exists(os.path.join(git_dir, "shallow"))
        completeness = HistoryCompleteness.PARTIAL if is_shallow else HistoryCompleteness.COMPLETE

        # Total commits count
        rev_list = self._run_git(["rev-list", "--count", "HEAD"], cwd=root) or "0"
        try:
            total_commits = int(rev_list.strip())
        except ValueError:
            total_commits = 0

        remotes = self.get_remotes()
        hooks = self.get_hooks()

        return GitRepositoryMetadata(
            repository_root=root,
            head_commit=head_hash,
            default_branch="main" if "main" in branches else ("master" if "master" in branches else (branches[0] if branches else "main")),
            branches=branches,
            tags=tags,
            total_commits=total_commits,
            is_shallow=is_shallow,
            completeness=completeness,
            remotes=remotes,
            hooks=hooks,
        )

    def get_commits(
        self,
        max_count: int | None = None,
        since: str | None = None,
        path_filter: str | None = None,
    ) -> list[GitCommit]:
        root = self.get_repository_root()
        if not root or not self.is_valid_repository():
            return []

        # Format: HASH|AUTHOR|EMAIL|DATE|SUBJECT|PARENTS
        cmd = ["log", "--name-status", "--pretty=format:---COMMIT---%n%H|%an|%ae|%aI|%s|%P%n%b"]
        if max_count:
            cmd.append(f"-n{max_count}")
        if since:
            cmd.append(f"--since={since}")

        if path_filter:
            cmd.extend(["--", path_filter])

        raw_output = self._run_git(cmd, cwd=root)
        if not raw_output:
            return []

        commits: list[GitCommit] = []
        raw_blocks = raw_output.split("---COMMIT---\n")

        for block in raw_blocks:
            block = block.strip()
            if not block:
                continue

            lines = block.splitlines()
            if not lines:
                continue

            header_parts = lines[0].split("|")
            if len(header_parts) < 5:
                continue

            c_hash = header_parts[0]
            author_name = header_parts[1]
            author_email = header_parts[2]
            timestamp = header_parts[3]
            subject = header_parts[4]
            parents = header_parts[5].split() if len(header_parts) > 5 and header_parts[5] else []

            msg_lines = []
            files_changed: list[GitFileChange] = []

            for line in lines[1:]:
                line_str = line.strip()
                if not line_str:
                    continue

                # Status lines: e.g. "A\tpath", "M\tpath", "D\tpath", "R100\told_path\tnew_path"
                if line[0] in ("A", "M", "D", "R", "C") and ("\t" in line or " " in line):
                    parts = line.split()
                    status_code = parts[0]
                    if status_code.startswith("A"):
                        change_type = ChangeType.ADDED
                        f_path = parts[1] if len(parts) > 1 else ""
                        files_changed.append(GitFileChange(file_path=f_path, change_type=change_type))
                    elif status_code.startswith("M"):
                        change_type = ChangeType.MODIFIED
                        f_path = parts[1] if len(parts) > 1 else ""
                        files_changed.append(GitFileChange(file_path=f_path, change_type=change_type))
                    elif status_code.startswith("D"):
                        change_type = ChangeType.DELETED
                        f_path = parts[1] if len(parts) > 1 else ""
                        files_changed.append(GitFileChange(file_path=f_path, change_type=change_type))
                    elif status_code.startswith("R"):
                        change_type = ChangeType.RENAMED
                        old_p = parts[1] if len(parts) > 1 else ""
                        new_p = parts[2] if len(parts) > 2 else old_p
                        files_changed.append(GitFileChange(file_path=new_p, change_type=change_type, old_path=old_p))
                else:
                    msg_lines.append(line_str)

            commits.append(
                GitCommit(
                    commit_hash=c_hash,
                    author_name=author_name,
                    author_email=author_email,
                    timestamp=timestamp,
                    subject=subject,
                    message="\n".join(msg_lines),
                    parents=parents,
                    files_changed=files_changed,
                )
            )

        return commits

    def get_commit(self, commit_hash: str) -> GitCommit | None:
        commits = self.get_commits(max_count=1, since=None, path_filter=None)
        return commits[0] if commits else None

    def get_file_content_at_commit(self, commit_hash: str, file_path: str) -> str | None:
        root = self.get_repository_root()
        if not root:
            return None
        rel_path = os.path.relpath(file_path, root) if os.path.isabs(file_path) else file_path
        # Use git cat-file -p commit:path
        output = self._run_git(["cat-file", "-p", f"{commit_hash}:{rel_path}"], cwd=root)
        return output

    def get_diff(self, commit_hash: str) -> str:
        root = self.get_repository_root()
        if not root:
            return ""
        output = self._run_git(["show", "--pretty=", "-p", commit_hash], cwd=root)
        return output or ""

    def get_remotes(self) -> list[GitRemoteInfo]:
        root = self.get_repository_root()
        if not root:
            return []

        raw_remotes = self._run_git(["remote", "-v"], cwd=root) or ""
        remotes: list[GitRemoteInfo] = []
        seen: set[str] = set()

        for line in raw_remotes.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            parts = line_str.split()
            if len(parts) >= 2:
                r_name = parts[0]
                r_url = parts[1]
                if r_name in seen:
                    continue
                seen.add(r_name)

                # Check embedded credentials: e.g. https://user:pass@host/repo.git or git@user:pass
                has_creds = bool(re.search(r"https?://[^:@]+:[^@]+@", r_url))
                remotes.append(GitRemoteInfo(name=r_name, url=r_url, has_embedded_credentials=has_creds))

        return remotes

    def get_hooks(self) -> list[GitHookInfo]:
        root = self.get_repository_root()
        if not root:
            return []

        hooks_dir = os.path.join(root, ".git", "hooks")
        if not os.path.exists(hooks_dir) or not os.path.isdir(hooks_dir):
            return []

        hooks: list[GitHookInfo] = []
        suspicious_keywords = ["curl", "wget", "eval", "nc ", "netcat", "/dev/tcp", "python -c", "bash -i"]

        for file_name in os.listdir(hooks_dir):
            if file_name.endswith(".sample"):
                continue
            hook_path = os.path.join(hooks_dir, file_name)
            if os.path.isfile(hook_path):
                is_active = os.access(hook_path, os.X_OK)
                suspicious_reasons: list[str] = []
                try:
                    with open(hook_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for kw in suspicious_keywords:
                        if kw in content:
                            suspicious_reasons.append(f"Contains suspicious command keyword: '{kw}'")
                except Exception:
                    pass

                hooks.append(
                    GitHookInfo(
                        name=file_name,
                        path=hook_path,
                        is_active=is_active,
                        is_suspicious=bool(suspicious_reasons),
                        suspicious_reasons=suspicious_reasons,
                    )
                )

        return hooks

    def _run_git(self, args: list[str], cwd: str) -> str | None:
        """Safely execute git sub-command array with timeout and read-only guarantee."""
        full_cmd = ["git"] + args
        try:
            res = subprocess.run(
                full_cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except Exception:
            return None
