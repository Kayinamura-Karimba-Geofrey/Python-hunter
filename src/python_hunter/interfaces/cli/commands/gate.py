"""CLI subcommand: gate."""

import argparse
import sys

from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.correlation.correlator import FindingCorrelator
from python_hunter.domain.correlation.risk_engine import RiskEngine
from python_hunter.domain.policy.engine import SecurityPolicyEngine


def run_gate_command(args: argparse.Namespace) -> int:
    """Execute CI/CD security gate policy check.
    
    Exit codes:
      0 = Pass
      1 = Policy Violation
      2 = Analysis Error
      3 = Configuration Error
    """
    use_case = AnalyzeSecurityUseCase()
    try:
        findings, _, _ = use_case.execute(args.target)
    except Exception as e:
        print(f"Analysis Error: {e}", file=sys.stderr)
        return 2

    policy_engine = SecurityPolicyEngine.from_config_file(
        f"{args.target}/pyh_policy.yml" if args.target.endswith("/") else f"{args.target}/pyh_policy.yml"
    )

    correlator = FindingCorrelator()
    deduped, attack_paths = correlator.correlate(findings)
    risk_engine = RiskEngine()
    risk_engine.score_findings(deduped)
    posture = risk_engine.calculate_posture(deduped, attack_paths)

    passed, violations = policy_engine.evaluate(deduped, posture.project_risk_score)

    print("==========================================================")
    print(" Python Hunter CI/CD Security Gate Evaluation")
    print("==========================================================")
    print(f"Target Path            : {args.target}")
    print(f"Overall Risk Score     : {posture.project_risk_score}/100")
    print(f"Security Gate Result   : {'PASSED' if passed else 'FAILED'}")
    print("==========================================================")

    if not passed:
        print("\n[!] Policy Violations Detected:")
        for v in violations:
            print(f"  • {v}")
        return 1

    print("\n[+] Security Gate Passed successfully.")
    return 0
