"""Standalone Test Runner for Python Hunter."""

import os
import sys
import unittest

# Ensure src/ is on PYTHONPATH
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)


def run_all_tests() -> bool:
    """Discover and execute all test suites under tests/."""
    start_dir = os.path.dirname(__file__)
    suite = unittest.defaultTestLoader.discover(start_dir=start_dir, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
