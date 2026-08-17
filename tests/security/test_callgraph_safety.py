"""Security & safety tests for Static Call Graph Engine."""

import os
import unittest

from python_hunter.application.use_cases.analyze_callgraph import AnalyzeCallGraphUseCase


class TestCallGraphSafety(unittest.TestCase):
    """Test suite verifying static program-analysis safety guarantees."""

    def test_no_code_execution_during_callgraph_analysis(self) -> None:
        """Verify that dynamic expressions or imports in target source file are not executed."""
        malicious_code_path = "/tmp/test_callgraph_malicious.py"
        with open(malicious_code_path, "w", encoding="utf-8") as f:
            f.write("import os\nos.system('echo EXECUTED > /tmp/callgraph_executed_marker')\n")

        marker_path = "/tmp/callgraph_executed_marker"
        if os.path.exists(marker_path):
            os.remove(marker_path)

        use_case = AnalyzeCallGraphUseCase()
        use_case.execute(malicious_code_path)

        self.assertFalse(os.path.exists(marker_path), "Call graph engine executed target source code!")


if __name__ == "__main__":
    unittest.main()
