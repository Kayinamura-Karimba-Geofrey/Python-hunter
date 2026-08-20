"""Repository configuration file (.python-hunter.yml) parser and validator."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class GitHubBehaviorConfig:
    scan_on_push: bool = True
    scan_on_pr: bool = True
    scan_on_merge: bool = True
    comments_enabled: bool = True
    annotations_enabled: bool = True
    check_runs_enabled: bool = True
    max_annotations: int = 50


@dataclass
class RepoSecurityConfig:
    scan_profile: str = "strict"
    policy_name: str = "default"
    excluded_paths: List[str] = field(default_factory=lambda: ["vendor/", "node_modules/", "tests/"])
    score_threshold: int = 70
    github_behavior: GitHubBehaviorConfig = field(default_factory=GitHubBehaviorConfig)


class RepoConfigParser:
    """Parses and validates .python-hunter.yml files."""

    @staticmethod
    def parse_yaml(content: str) -> RepoSecurityConfig:
        """Parses YAML content into RepoSecurityConfig dataclass."""
        raw_data = {}
        if yaml is not None:
            try:
                raw_data = yaml.safe_load(content) or {}
            except Exception as e:
                raise ValueError(f"Invalid YAML configuration in .python-hunter.yml: {e}")
        else:
            # Fallback simple line parser for environments without PyYAML
            for line in content.splitlines():
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if v.isdigit():
                        raw_data[k] = int(v)
                    elif v in ("true", "True"):
                        raw_data[k] = True
                    elif v in ("false", "False"):
                        raw_data[k] = False
                    elif v:
                        raw_data[k] = v

        if not isinstance(raw_data, dict):
            raise ValueError(".python-hunter.yml must contain a dictionary mapping.")

        gh_data = raw_data.get("github", {})
        github_behavior = GitHubBehaviorConfig(
            scan_on_push=gh_data.get("scan_on_push", True),
            scan_on_pr=gh_data.get("scan_on_pr", True),
            scan_on_merge=gh_data.get("scan_on_merge", True),
            comments_enabled=gh_data.get("comments_enabled", True),
            annotations_enabled=gh_data.get("annotations_enabled", True),
            check_runs_enabled=gh_data.get("check_runs_enabled", True),
            max_annotations=min(gh_data.get("max_annotations", 50), 100),
        )

        return RepoSecurityConfig(
            scan_profile=raw_data.get("scan_profile", "strict"),
            policy_name=raw_data.get("policy_name", "default"),
            excluded_paths=raw_data.get("excluded_paths", ["vendor/", "node_modules/", "tests/"]),
            score_threshold=raw_data.get("score_threshold", 70),
            github_behavior=github_behavior,
        )

    @staticmethod
    def validate_against_server_policy(
        repo_config: RepoSecurityConfig,
        server_policy: Dict[str, Any],
    ) -> RepoSecurityConfig:
        """Enforces that repository configuration cannot bypass server-enforced mandatory security policies."""
        # E.g., server policy can mandate minimum score_threshold or force scan_on_pr
        min_allowed_threshold = server_policy.get("min_score_threshold", 60)
        if repo_config.score_threshold < min_allowed_threshold:
            repo_config.score_threshold = min_allowed_threshold

        if server_policy.get("force_pr_scans", True):
            repo_config.github_behavior.scan_on_pr = True

        return repo_config
