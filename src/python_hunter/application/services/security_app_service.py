"""Unified SecurityApplicationService providing shared application logic for CLI and API."""

from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.domain.history.history_engine import SecurityHistoryStore, SnapshotComparator
from python_hunter.domain.policy.policy_evaluator import PolicyEngine


class SecurityApplicationService:
    """Unified application service wrapping scanning, policy evaluation, history tracking, and reporting."""

    def __init__(self) -> None:
        self.orchestrator = ScanOrchestrator()
        self.policy_engine = PolicyEngine()
        self.history_store = SecurityHistoryStore()
        self.comparator = SnapshotComparator()

    def get_system_info(self) -> dict:
        return {
            "name": "Python Hunter",
            "version": "1.0.0",
            "supported_languages": ["Python", "JavaScript", "TypeScript"],
            "supported_frameworks": ["Django", "Flask", "FastAPI", "Express", "NestJS"],
            "status": "OPERATIONAL",
        }

    def execute_scan(self, target_path: str, profile: str = "strict") -> dict:
        scan_result = self.orchestrator.run_scan(target_path)
        findings = scan_result.findings
        risk_score = scan_result.risk_summary.get("total_risk_score", 0.0) if hasattr(scan_result, "risk_summary") else 0.0

        gate_result = self.policy_engine.evaluate_gate(findings, risk_score=risk_score, profile=profile)

        return {
            "target": target_path,
            "findings_count": len(findings),
            "risk_score": risk_score,
            "gate_status": gate_result.status.value,
            "violations": gate_result.violations,
            "exit_code": gate_result.exit_code,
        }
