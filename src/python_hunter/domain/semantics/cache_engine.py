"""Analysis Cache Engine with incremental invalidation and bounded execution limits."""

from dataclasses import dataclass, field
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Set


@dataclass
class AnalysisLimits:
    max_call_depth: int = 10
    max_graph_nodes: int = 5000
    max_paths: int = 100
    max_analysis_time_seconds: float = 30.0
    max_memory_mb: int = 512


@dataclass
class LimitationReport:
    reached_timeout: bool = False
    reached_max_depth: bool = False
    reached_max_paths: bool = False
    skipped_nodes_count: int = 0
    warnings: List[str] = field(default_factory=list)


@dataclass
class CacheEntry:
    workspace_hash: str
    file_hashes: Dict[str, str]
    rule_versions: Dict[str, str]
    cached_model: Any
    timestamp: float


class AnalysisCacheEngine:
    """Cache engine supporting incremental invalidation and analysis limit enforcement."""

    def __init__(self, limits: Optional[AnalysisLimits] = None) -> None:
        self.limits = limits or AnalysisLimits()
        self._cache: Dict[str, CacheEntry] = {}
        self.start_time: float = 0.0

    def compute_file_hash(self, file_path: str) -> str:
        if not os.path.exists(file_path):
            return ""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                hasher.update(f.read())
            return hasher.hexdigest()
        except Exception:
            return ""

    def get_workspace_hash(self, workspace_path: str) -> str:
        hasher = hashlib.sha256()
        for root, _, files in os.walk(workspace_path):
            for file in sorted(files):
                if file.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb")):
                    full_path = os.path.join(root, file)
                    hasher.update(self.compute_file_hash(full_path).encode("utf-8"))
        return hasher.hexdigest()

    def get_cached_analysis(self, workspace_path: str, rule_versions: Dict[str, str]) -> Optional[Any]:
        current_hash = self.get_workspace_hash(workspace_path)
        entry = self._cache.get(workspace_path)
        if not entry:
            return None

        # Check invalidation conditions: workspace hash or rule versions change
        if entry.workspace_hash != current_hash or entry.rule_versions != rule_versions:
            return None

        return entry.cached_model

    def store_cached_analysis(self, workspace_path: str, rule_versions: Dict[str, str], model: Any) -> None:
        file_hashes = {}
        for root, _, files in os.walk(workspace_path):
            for file in files:
                full_path = os.path.join(root, file)
                file_hashes[full_path] = self.compute_file_hash(full_path)

        self._cache[workspace_path] = CacheEntry(
            workspace_hash=self.get_workspace_hash(workspace_path),
            file_hashes=file_hashes,
            rule_versions=rule_versions,
            cached_model=model,
            timestamp=time.time(),
        )

    def start_timer(self) -> None:
        self.start_time = time.time()

    def is_timeout(self) -> bool:
        if self.start_time <= 0:
            return False
        return (time.time() - self.start_time) > self.limits.max_analysis_time_seconds
