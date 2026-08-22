"""Verification Planner, Allowlist/Denylist Safety Validator, and Authorization Engine."""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from python_hunter.domain.common.enums import (
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


# Denied networks / endpoints — NEVER allow active testing against these
DENYLIST_PATTERNS = [
    r"169\.254\.169\.254",  # AWS/GCP Instance Metadata Service
    r"metadata\.google\.internal",
    r"100\.100\.100\.200",  # Alibaba Metadata
    r".*\.amazonaws\.com",
    r".*\.googleapis\.com",
    r".*\.azure\.com",
    r".*\.production\..*",
    r"prod-.*",
]

ALLOWLIST_PATTERNS = [
    r"^localhost$",
    r"^127\.0\.0\.1$",
    r"^0\.0\.0\.0$",
    r"^::1$",
    r".*\.local$",
    r".*\.test$",
]


class SafetyValidator:
    """Validates target URLs, IP addresses, and environments for active verification safety."""

    @staticmethod
    def is_target_allowed(target: str) -> Tuple[bool, str]:
        """Validates target against denylist and allowlist rules."""
        if not target:
            return False, "Target address/URL cannot be empty."

        # Parse target domain or IP
        clean_target = target
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            clean_target = parsed.hostname or target

        # Check Denylist
        for denypat in DENYLIST_PATTERNS:
            if re.search(denypat, clean_target, re.IGNORECASE):
                return False, f"Target '{target}' matches restricted denylist pattern '{denypat}'. Active verification blocked."

        # Check Allowlist
        allowed = any(re.search(allowpat, clean_target, re.IGNORECASE) for allowpat in ALLOWLIST_PATTERNS)
        if not allowed:
            return False, f"Target '{target}' is not in the authorized local test allowlist. Active verification blocked."

        return True, "Target is safely authorized for non-destructive local verification."


class VerificationPlanner:
    """Determines eligibility, safety level, and test strategy for findings."""

    def __init__(self, safe_mode: bool = False) -> None:
        self.safe_mode = safe_mode
        self.validator = SafetyValidator()

    def plan_verification(
        self,
        finding: Dict[str, Any],
        mode: VerificationMode = VerificationMode.PASSIVE,
        authorization: Optional[VerificationAuthorization] = None,
        target: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[SecurityTest]]:
        """Evaluates whether a finding can be safely verified under current mode & authorization."""
        rule_id = str(finding.get("rule_id", ""))
        vuln_type = self._map_rule_to_vuln_type(rule_id, finding.get("title", ""))

        if self.safe_mode:
            if mode == VerificationMode.ACTIVE:
                return False, "SAFE MODE is active. Active verification is strictly disabled.", None

        if mode == VerificationMode.PASSIVE:
            return True, "Passive static verification plan approved.", None

        # Active Verification Gate Checks
        if not authorization:
            return False, "Active verification requires explicit --authorized-target and valid authorization record.", None

        if not authorization.is_valid:
            return False, "Verification authorization has expired. Please re-authorize.", None

        effective_target = target or authorization.target
        is_allowed, reason = self.validator.is_target_allowed(effective_target)
        if not is_allowed:
            return False, reason, None

        safe_test = SafePayloadRegistry.get_safe_test(vuln_type)
        if not safe_test:
            return False, f"No safe non-destructive test case registered for category '{vuln_type}'.", None

        return True, f"Active non-destructive verification approved for target '{effective_target}'.", safe_test

    @staticmethod
    def _map_rule_to_vuln_type(rule_id: str, title: str) -> str:
        r_upper = rule_id.upper()
        t_upper = title.upper()
        if "SQL" in r_upper or "SQL" in t_upper:
            return "SQL_INJECTION"
        elif "SYSTEM" in r_upper or "EVAL" in r_upper or "EXEC" in r_upper or "COMMAND" in t_upper:
            return "COMMAND_INJECTION"
        elif "PATH" in r_upper or "TRAVERSAL" in t_upper or "FILE" in r_upper:
            return "PATH_TRAVERSAL"
        elif "SSRF" in r_upper or "SSRF" in t_upper:
            return "SSRF"
        elif "AUTH" in r_upper:
            return "AUTHENTICATION"
        elif "DEP" in r_upper or "SCA" in r_upper:
            return "DEPENDENCY"
        return "GENERIC"
