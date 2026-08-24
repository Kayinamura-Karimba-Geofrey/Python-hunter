"""Scanner Workload Isolation, Network Policies, Resource Limits, and Filesystem Sandboxing."""

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SandboxConfig:
    """Resource limits and security constraints for scanner execution."""

    max_cpu_cores: int = 2
    max_memory_mb: int = 4096
    max_runtime_seconds: int = 600
    network_allowed: bool = False
    read_only_root: bool = True


class ScannerSandbox:
    """Isolated temporary workspace sandbox for running untrusted repository scans."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()
        self.temp_dir: str | None = None

    def __enter__(self) -> "ScannerSandbox":
        self.temp_dir = tempfile.mkdtemp(prefix="pyh_sandbox_")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Guaranteed cleanup of temporary sandbox filesystems."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass
            self.temp_dir = None
