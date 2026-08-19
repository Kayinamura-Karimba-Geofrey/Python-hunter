"""Target Resolver and ScanTarget models for Python Hunter."""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TargetType(str, Enum):
    """Types of scan targets supported by Python Hunter."""

    LOCAL_DIRECTORY = "LOCAL_DIRECTORY"
    LOCAL_FILE = "LOCAL_FILE"
    GIT_REPOSITORY = "GIT_REPOSITORY"
    GITHUB_REPOSITORY = "GITHUB_REPOSITORY"


@dataclass
class ScanTarget:
    """Normalized scan target representation."""

    target_type: TargetType
    source: str
    local_path: str
    repository_url: str = ""
    branch: str = ""
    commit: str = ""
    tag: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class TargetResolver:
    """Resolves and normalizes target paths and repository URLs."""

    GITHUB_URL_REGEX = re.compile(
        r"^(https://github\.com/|git@github\.com:)(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(\.git)?$"
    )

    def resolve(
        self,
        target_str: str,
        branch: str = "",
        commit: str = "",
        tag: str = "",
    ) -> ScanTarget:
        """Resolves target string into a normalized ScanTarget."""
        target_str = target_str.strip()

        # Check GitHub HTTPS/SSH URL
        match = self.GITHUB_URL_REGEX.match(target_str)
        if match:
            owner = match.group("owner")
            repo = match.group("repo")
            norm_url = f"https://github.com/{owner}/{repo}.git"
            return ScanTarget(
                target_type=TargetType.GITHUB_REPOSITORY,
                source=target_str,
                local_path="",
                repository_url=norm_url,
                branch=branch,
                commit=commit,
                tag=tag,
                metadata={"owner": owner, "repo": repo},
            )

        # Check local path
        abs_path = os.path.abspath(target_str)
        if os.path.isdir(abs_path):
            is_git = os.path.isdir(os.path.join(abs_path, ".git"))
            return ScanTarget(
                target_type=TargetType.GIT_REPOSITORY if is_git else TargetType.LOCAL_DIRECTORY,
                source=target_str,
                local_path=abs_path,
                branch=branch,
                commit=commit,
                tag=tag,
            )
        elif os.path.isfile(abs_path):
            return ScanTarget(
                target_type=TargetType.LOCAL_FILE,
                source=target_str,
                local_path=abs_path,
                branch=branch,
                commit=commit,
                tag=tag,
            )
        else:
            raise ValueError(f"Invalid target path or repository URL: '{target_str}'")
