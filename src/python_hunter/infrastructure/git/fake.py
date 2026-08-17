"""Deterministic In-Memory Fake Git Repository Provider for Testing."""

from python_hunter.domain.git.interfaces import GitRepository
from python_hunter.domain.git.models import (
    GitCommit,
    GitHookInfo,
    GitRemoteInfo,
    GitRepositoryMetadata,
    HistoryCompleteness,
)


class FakeGitRepository(GitRepository):
    """In-memory mock Git repository loaded with pre-configured synthetic commits and metadata."""

    def __init__(
        self,
        repository_root: str = "/fake/repo",
        commits: list[GitCommit] | None = None,
        file_contents: dict[tuple[str, str], str] | None = None,
        diffs: dict[str, str] | None = None,
        remotes: list[GitRemoteInfo] | None = None,
        hooks: list[GitHookInfo] | None = None,
        is_shallow: bool = False,
    ) -> None:
        self._repo_root = repository_root
        self.commits_list: list[GitCommit] = commits or []
        self.file_contents_map: dict[tuple[str, str], str] = file_contents or {}
        self.diffs_map: dict[str, str] = diffs or {}
        self.remotes_list: list[GitRemoteInfo] = remotes or []
        self.hooks_list: list[GitHookInfo] = hooks or []
        self.is_shallow_flag = is_shallow
        self.valid_repo = True

    def is_valid_repository(self) -> bool:
        return self.valid_repo

    def get_repository_root(self) -> str:
        return self._repo_root

    def get_metadata(self) -> GitRepositoryMetadata:
        head = self.commits_list[0].commit_hash if self.commits_list else "0000000"
        completeness = HistoryCompleteness.PARTIAL if self.is_shallow_flag else HistoryCompleteness.COMPLETE
        return GitRepositoryMetadata(
            repository_root=self._repo_root,
            head_commit=head,
            default_branch="main",
            branches=["main"],
            tags=["v1.0.0"],
            total_commits=len(self.commits_list),
            is_shallow=self.is_shallow_flag,
            completeness=completeness,
            remotes=self.remotes_list,
            hooks=self.hooks_list,
        )

    def get_commits(
        self,
        max_count: int | None = None,
        since: str | None = None,
        path_filter: str | None = None,
    ) -> list[GitCommit]:
        results = list(self.commits_list)
        if path_filter:
            results = [
                c for c in results
                if any(fc.file_path == path_filter for fc in c.files_changed)
            ]
        if max_count:
            results = results[:max_count]
        return results

    def get_commit(self, commit_hash: str) -> GitCommit | None:
        for c in self.commits_list:
            if c.commit_hash == commit_hash or c.commit_hash.startswith(commit_hash):
                return c
        return None

    def get_file_content_at_commit(self, commit_hash: str, file_path: str) -> str | None:
        return self.file_contents_map.get((commit_hash, file_path))

    def get_diff(self, commit_hash: str) -> str:
        return self.diffs_map.get(commit_hash, "")

    def get_remotes(self) -> list[GitRemoteInfo]:
        return self.remotes_list

    def get_hooks(self) -> list[GitHookInfo]:
        return self.hooks_list
