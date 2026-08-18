"""Run CI Application Use Case."""

import os
import sys
from typing import Any

from python_hunter.application.use_cases.generate_report import GenerateReportUseCase
from python_hunter.domain.baseline.engine import BaselineEngine


class RunCIUseCase:
    """Orchestrates non-interactive CI pipeline execution, artifact export, and exit code evaluation."""

    def __init__(self, report_use_case: GenerateReportUseCase | None = None) -> None:
        self.report_use_case = report_use_case or GenerateReportUseCase()

    def execute(
        self,
        target_path: str,
        export_artifacts: bool = True,
        output_dir: str = ".",
        options: dict[str, Any] | None = None,
    ) -> int:
        """Execute CI pipeline flow.
        
        Exit codes:
          0 = Policy PASSED
          1 = Policy FAILED / Violations
          2 = Analysis Execution Error
          3 = Policy Configuration Error
        """
        try:
            report = self.report_use_case.build_report(target_path)
        except Exception as e:
            sys.stderr.write(f"CI Analysis Error: {e}\n")
            return 2

        # Optional artifact generation
        if export_artifacts:
            os.makedirs(output_dir, exist_ok=True)
            json_out = self.report_use_case.execute(target_path, format_name="json", options=options)
            sarif_out = self.report_use_case.execute(target_path, format_name="sarif", options=options)
            md_out = self.report_use_case.execute(target_path, format_name="markdown", options=options)

            with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
                f.write(json_out)
            with open(os.path.join(output_dir, "report.sarif"), "w", encoding="utf-8") as f:
                f.write(sarif_out)
            with open(os.path.join(output_dir, "report.md"), "w", encoding="utf-8") as f:
                f.write(md_out)

        # Print CI Summary output
        print("\n==========================================================")
        print(" Python Hunter CI Security Analysis Pipeline")
        print("==========================================================")
        print(f"Target Path            : {target_path}")
        print(f"Overall Risk Score     : {report.risk_metrics.project_risk_score}/100")
        print(f"New Findings           : {report.statistics.new_count}")
        print(f"Critical Findings      : {report.statistics.critical_count}")
        print(f"High Findings          : {report.statistics.high_count}")
        print(f"Medium Findings        : {report.statistics.medium_count}")
        print(f"Low Findings           : {report.statistics.low_count}")
        print(f"Policy Gate Status     : {'PASSED' if report.posture.policy_passed else 'FAILED'}")
        print("==========================================================")

        if not report.posture.policy_passed:
            print("\n[!] Policy Violations Detected:")
            for v in report.posture.policy_violations:
                print(f"  • {v}")
            return 1

        print("\n[+] Security Gate PASSED successfully.")
        return 0
