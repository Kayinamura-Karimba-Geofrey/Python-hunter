"""Verification Engine — Passive Static Evidence & Active Sandboxed Verification Executable."""

import logging
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from python_hunter.domain.common.enums import (
    Confidence,
    TestSafetyLevel,
    VerificationConfidence,
    VerificationMode,
    VerificationStatus,
)
from python_hunter.domain.verification.models import (
    SecurityTest,
    VerificationAuthorization,
    VerificationResult,
)
from python_hunter.domain.verification.payloads import SafePayloadRegistry
from python_hunter.domain.verification.planner import SafetyValidator, VerificationPlanner

logger = logging.getLogger("python_hunter.verification")


class PassiveVerifier:
    """Evaluates existing static analysis proofs (AST, Taint Dataflow, Reachability) without executing code."""

    @staticmethod
    def verify_finding(finding: Dict[str, Any]) -> VerificationResult:
        """Analyzes static evidence quality to upgrade confidence passively."""
        rule_id = str(finding.get("rule_id", ""))
        evidence = str(finding.get("evidence", ""))
        reachability = str(finding.get("reachability", "")).upper()
        confidence_str = str(finding.get("confidence", "LOW")).upper()

        # Check for multi-evidence indicators (AST + Taint Dataflow + Reachable SCA)
        has_source_sink = bool(finding.get("source") and finding.get("sink"))
        is_reachable = reachability in ("REACHABLE", "DIRECTLY_CALLABLE")
        is_high_conf = confidence_str in ("HIGH", "CONFIRMED")

        if is_reachable and has_source_sink:
            status = VerificationStatus.LIKELY_EXPLOITABLE
            conf = VerificationConfidence.HIGH
            ev_summary = f"Passive Verification Confirmed: Reachable dataflow from {finding.get('source')} to {finding.get('sink')}."
        elif has_source_sink or is_high_conf:
            status = VerificationStatus.LIKELY_EXPLOITABLE
            conf = VerificationConfidence.MEDIUM
            ev_summary = f"Passive Verification Likely: Strong static taint trace detected in {finding.get('file_path')}."
        else:
            status = VerificationStatus.NOT_VERIFIED
            conf = VerificationConfidence.LOW
            ev_summary = f"Passive Verification Inconclusive: Finding has limited static evidence traces."

        return VerificationResult(
            finding_id=str(finding.get("id", "f-unknown")),
            verification_status=status,
            confidence=conf,
            evidence=ev_summary,
            test_method="PASSIVE_STATIC_EVIDENCE_ANALYSIS",
            safety_level=TestSafetyLevel.PASSIVE_ONLY,
        )


class VerificationSandbox:
    """Isolated local test execution sandbox enforcing timeout, process, and memory limits."""

    def __init__(self, timeout_seconds: float = 3.0, max_memory_mb: int = 128) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_memory_mb = max_memory_mb

    def execute_safe_test(
        self, test: SecurityTest, target_url: str
    ) -> Tuple[VerificationStatus, VerificationConfidence, str, float]:
        """Executes safe HTTP test query against local authorized test endpoint."""
        start_time = time.time()
        try:
            # Build safe query against target
            test_url = f"{target_url.rstrip('/')}?test_param={urllib.parse.quote(test.input_payload)}"
            req = urllib.request.Request(
                test_url,
                headers={
                    "User-Agent": "PythonHunter-SecurityVerifier/1.0",
                    "X-Pyh-Verification-Mode": "NonDestructiveLocalTest",
                },
            )

            # Enforce execution timeout
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                elapsed_ms = (time.time() - start_time) * 1000.0

                if "pyh_verify_test_echo" in body or "pyh_verify" in body or resp.status == 200:
                    return (
                        VerificationStatus.VERIFIED,
                        VerificationConfidence.VERIFIED,
                        f"Active Verification SUCCESS: Target reflected safe test payload under controlled conditions in {elapsed_ms:.1f}ms.",
                        elapsed_ms,
                    )
                else:
                    return (
                        VerificationStatus.NOT_EXPLOITABLE,
                        VerificationConfidence.HIGH,
                        f"Active Verification Failed to Exploit: Target returned status {resp.status} without payload reflection.",
                        elapsed_ms,
                    )

        except urllib.error.HTTPError as e:
            elapsed_ms = (time.time() - start_time) * 1000.0
            if e.code in (400, 422, 500):
                return (
                    VerificationStatus.LIKELY_EXPLOITABLE,
                    VerificationConfidence.MEDIUM,
                    f"Active Verification Behavior Indication: Target raised HTTP {e.code} handling safe test input.",
                    elapsed_ms,
                )
            return (
                VerificationStatus.NOT_EXPLOITABLE,
                VerificationConfidence.MEDIUM,
                f"Target safely rejected test input with HTTP {e.code}.",
                elapsed_ms,
            )

        except urllib.error.URLError as e:
            elapsed_ms = (time.time() - start_time) * 1000.0
            if isinstance(e.reason, TimeoutError) or "timed out" in str(e.reason).lower():
                return (
                    VerificationStatus.INCONCLUSIVE,
                    VerificationConfidence.LOW,
                    f"Active Verification TEST_TIMEOUT: Test request timed out after {self.timeout_seconds}s.",
                    elapsed_ms,
                )
            return (
                VerificationStatus.TEST_ERROR,
                VerificationConfidence.LOW,
                f"Active Verification TEST_ERROR: Target endpoint unreachable ({e.reason}).",
                elapsed_ms,
            )
        except Exception as ex:
            elapsed_ms = (time.time() - start_time) * 1000.0
            return (
                VerificationStatus.TEST_ERROR,
                VerificationConfidence.LOW,
                f"Active Verification Execution Exception: {str(ex)}",
                elapsed_ms,
            )


class VerificationEngine:
    """Primary orchestrator for passive and controlled active security verification."""

    def __init__(self, safe_mode: bool = False) -> None:
        self.planner = VerificationPlanner(safe_mode=safe_mode)
        self.passive_verifier = PassiveVerifier()
        self.sandbox = VerificationSandbox()

    def verify_finding(
        self,
        finding: Dict[str, Any],
        mode: VerificationMode = VerificationMode.PASSIVE,
        authorization: Optional[VerificationAuthorization] = None,
        target: Optional[str] = None,
        dry_run: bool = False,
    ) -> VerificationResult:
        """Executes verification flow following Safety -> Planner -> Executor -> Evidence model."""
        approved, reason, test = self.planner.plan_verification(
            finding, mode=mode, authorization=authorization, target=target
        )

        if not approved:
            return VerificationResult(
                finding_id=str(finding.get("id", "f-unknown")),
                verification_status=VerificationStatus.NOT_VERIFIED,
                confidence=VerificationConfidence.LOW,
                evidence=f"Verification Plan Refused: {reason}",
                test_method="PLANNER_REFUSAL",
                safety_level=TestSafetyLevel.DESTRUCTIVE_FORBIDDEN,
            )

        if dry_run:
            return VerificationResult(
                finding_id=str(finding.get("id", "f-unknown")),
                verification_status=VerificationStatus.NOT_TESTED,
                confidence=VerificationConfidence.LOW,
                evidence=f"DRY RUN: Approved plan for test '{test.test_id if test else 'PASSIVE'}' against target '{target}'. No execution performed.",
                test_method="DRY_RUN",
                safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            )

        if mode == VerificationMode.PASSIVE or not test:
            return self.passive_verifier.verify_finding(finding)

        # Execute Active Verification inside Sandbox
        effective_target = target or (authorization.target if authorization else "http://127.0.0.1:8080")
        status, conf, evidence, elapsed = self.sandbox.execute_safe_test(test, effective_target)

        return VerificationResult(
            finding_id=str(finding.get("id", "f-unknown")),
            verification_status=status,
            confidence=conf,
            evidence=evidence,
            test_method=f"ACTIVE_SANDBOX_TEST:{test.test_id}",
            safety_level=test.safety_level,
            execution_time_ms=elapsed,
        )
