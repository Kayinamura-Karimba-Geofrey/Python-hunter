import os
import unittest

from python_hunter.application.use_cases.analyze_taint import AnalyzeTaintUseCase


class TestTaintSafety(unittest.TestCase):
    """Test suite verifying static analysis safety guarantees."""

    def test_no_code_execution_during_taint_analysis(self) -> None:
        """Verify that dynamic expressions like print/exec in source file are not executed."""
        malicious_code_path = "/tmp/test_malicious.py"
        with open(malicious_code_path, "w", encoding="utf-8") as f:
            f.write("import os\n# If executed, this would write a marker file\nos.system('echo EXECUTED > /tmp/taint_executed_marker')\n")

        # Ensure marker does not exist
        marker_path = "/tmp/taint_executed_marker"
        if os.path.exists(marker_path):
            os.remove(marker_path)

        use_case = AnalyzeTaintUseCase()
        use_case.execute(malicious_code_path)

        # Confirm code was NOT executed
        self.assertFalse(os.path.exists(marker_path), "Taint engine executed target source code!")


if __name__ == "__main__":
    unittest.main()
