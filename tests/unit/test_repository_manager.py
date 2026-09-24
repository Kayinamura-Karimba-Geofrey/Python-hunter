"""Unit tests for RepositoryManager, progress-aware watchdog, and clone timeouts."""

import os
import sys
import unittest
from unittest.mock import patch

from python_hunter.infrastructure.repository.repository_manager import (
    RepositoryManager,
    _run_git_with_watchdog,
)
from python_hunter.infrastructure.repository.target_resolver import ScanTarget, TargetType


class TestRepositoryManagerWatchdog(unittest.TestCase):
    """Test suite for activity watchdog and repository manager timeouts."""

    def test_watchdog_detects_stall_on_idle_timeout(self) -> None:
        """Verify that a silent process exceeding idle_timeout is terminated."""
        cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
        with self.assertRaises(RuntimeError) as ctx:
            _run_git_with_watchdog(
                cmd=cmd,
                env=os.environ.copy(),
                timeout=10,
                idle_timeout=1,
                show_progress=False,
                target_name="test_stall_repo",
            )
        self.assertIn("stalled", str(ctx.exception).lower())

    def test_watchdog_active_process_resets_idle_timer(self) -> None:
        """Verify that periodic output resets the idle timer and allows process completion."""
        script = (
            "import sys, time\n"
            "for i in range(3):\n"
            "    time.sleep(0.3)\n"
            "    sys.stderr.write(f'step {i}\\n')\n"
            "    sys.stderr.flush()\n"
        )
        cmd = [sys.executable, "-c", script]
        proc = _run_git_with_watchdog(
            cmd=cmd,
            env=os.environ.copy(),
            timeout=5,
            idle_timeout=1,
            show_progress=False,
            target_name="test_active_repo",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("step 2", proc.stderr)

    def test_watchdog_enforces_wall_clock_timeout_when_specified(self) -> None:
        """Verify that wall-clock timeout terminates process even if active."""
        script = (
            "import sys, time\n"
            "while True:\n"
            "    time.sleep(0.2)\n"
            "    sys.stderr.write('ping\\n')\n"
            "    sys.stderr.flush()\n"
        )
        cmd = [sys.executable, "-c", script]
        with self.assertRaises(RuntimeError) as ctx:
            _run_git_with_watchdog(
                cmd=cmd,
                env=os.environ.copy(),
                timeout=1,
                idle_timeout=5,
                show_progress=False,
                target_name="test_wallclock_repo",
            )
        self.assertIn("exceeded maximum wall-clock timeout", str(ctx.exception))

    def test_env_var_overrides_timeouts(self) -> None:
        """Verify GIT_CLONE_IDLE_TIMEOUT environment variable is respected."""
        cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
        with patch.dict(os.environ, {"GIT_CLONE_IDLE_TIMEOUT": "1"}):
            with self.assertRaises(RuntimeError) as ctx:
                _run_git_with_watchdog(
                    cmd=cmd,
                    env=os.environ.copy(),
                    timeout=None,
                    idle_timeout=None,
                    show_progress=False,
                    target_name="test_env_repo",
                )
            self.assertIn("stalled", str(ctx.exception).lower())

    def test_acquire_target_local_bypasses_clone(self) -> None:
        """Verify that local targets do not invoke cloning."""
        mgr = RepositoryManager()
        target = ScanTarget(
            target_type=TargetType.LOCAL_DIRECTORY,
            source=".",
            local_path=os.path.abspath("."),
        )
        path = mgr.acquire_target(target)
        self.assertEqual(path, os.path.abspath("."))
        self.assertEqual(len(mgr.temp_dirs), 0)

    def test_cleanup_removes_temp_dirs(self) -> None:
        """Verify that cleanup removes tracked temporary directories."""
        mgr = RepositoryManager()
        import tempfile
        d = tempfile.mkdtemp(prefix="pyh_test_clean_")
        mgr.temp_dirs.append(d)
        self.assertTrue(os.path.exists(d))
        mgr.cleanup()
        self.assertFalse(os.path.exists(d))
        self.assertEqual(len(mgr.temp_dirs), 0)


if __name__ == "__main__":
    unittest.main()
