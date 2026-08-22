"""Deterministic Safe Payload Registry and Secret Redactor."""

import re
from typing import Dict, List
from python_hunter.domain.verification.models import SecurityTest, TestSafetyLevel


class SafePayloadRegistry:
    """Provides minimal, safe, deterministic test payloads designed purely for non-destructive verification."""

    _PAYLOADS: Dict[str, SecurityTest] = {
        "SQL_INJECTION": SecurityTest(
            test_id="test-sqli-safe-01",
            vulnerability_type="SQL_INJECTION",
            preconditions=["parameter_injected"],
            input_payload="' AND 'pyh_verify'='pyh_verify",
            expected_behavior="Syntax check or boolean response reflection without DB mutation",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Boolean-based non-destructive SQL syntax test",
        ),
        "COMMAND_INJECTION": SecurityTest(
            test_id="test-cmdi-safe-01",
            vulnerability_type="COMMAND_INJECTION",
            preconditions=["shell_execution"],
            input_payload="; echo pyh_verify_test_echo",
            expected_behavior="Output contains 'pyh_verify_test_echo'",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Harmless echo command injection verification",
        ),
        "PATH_TRAVERSAL": SecurityTest(
            test_id="test-pathtraversal-safe-01",
            vulnerability_type="PATH_TRAVERSAL",
            preconditions=["file_access"],
            input_payload="../pyh_test_fixture.txt",
            expected_behavior="Accesses local test fixture outside target dir without touching sensitive OS files",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Local test fixture path escape verification",
        ),
        "SSRF": SecurityTest(
            test_id="test-ssrf-safe-01",
            vulnerability_type="SSRF",
            preconditions=["url_fetch"],
            input_payload="http://127.0.0.1:8080/pyh_health_check",
            expected_behavior="Queries controlled local test endpoint only",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Localhost controlled SSRF verification",
        ),
        "AUTHN_BYPASS": SecurityTest(
            test_id="test-authn-safe-01",
            vulnerability_type="AUTHENTICATION",
            preconditions=["test_account_configured"],
            input_payload="Bearer test_token_pyh_verify",
            expected_behavior="Validates auth header processing using safe test account",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Controlled test token verification",
        ),
        "AUTHZ_BYPASS": SecurityTest(
            test_id="test-authz-safe-01",
            vulnerability_type="AUTHORIZATION",
            preconditions=["test_identity_configured"],
            input_payload="X-Pyh-Test-Role: viewer",
            expected_behavior="Validates role-based access control against test route",
            safety_level=TestSafetyLevel.SAFE_LOCAL_NON_DESTRUCTIVE,
            description="Role isolation verification",
        ),
    }

    @classmethod
    def get_safe_test(cls, vulnerability_type: str) -> SecurityTest | None:
        """Retrieves registered safe test for vulnerability category."""
        return cls._PAYLOADS.get(vulnerability_type.upper())

    @staticmethod
    def redact_payload(text: str) -> str:
        """Redacts sensitive values or keys from verification logs/reports."""
        if not text:
            return ""
        redacted = re.sub(
            r"(?i)(api[_-]?key|secret|password|token|auth)\s*=\s*['\"]([^'\"]+)['\"]",
            r"\1='[REDACTED_VERIFICATION_PAYLOAD]'",
            text,
        )
        return redacted
