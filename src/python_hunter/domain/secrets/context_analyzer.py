"""Secret Context Analyzer and Test/Placeholder Classification Engine."""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.secrets.models import SecretEnvironment, SecretPrivilege, SecretType


class SecretContextAnalyzer:
    """Analyzes code/config context surrounding a secret candidate to determine environment, privilege, and candidate quality."""

    TEST_PATH_PATTERNS = [
        re.compile(r"[/\\]tests?[/\\]", re.IGNORECASE),
        re.compile(r"[/\\]fixtures?[/\\]", re.IGNORECASE),
        re.compile(r"[/\\]mocks?[/\\]", re.IGNORECASE),
        re.compile(r"test_[a-zA-Z0-9_-]+\.", re.IGNORECASE),
        re.compile(r"[a-zA-Z0-9_-]+\.spec\.", re.IGNORECASE),
        re.compile(r"[a-zA-Z0-9_-]+\.test\.", re.IGNORECASE),
    ]

    DOC_PATH_PATTERNS = [
        re.compile(r"[/\\]docs?[/\\]", re.IGNORECASE),
        re.compile(r"\.md$", re.IGNORECASE),
        re.compile(r"README", re.IGNORECASE),
    ]

    CI_CD_PATH_PATTERNS = [
        re.compile(r"[/\\]\.github[/\\]workflows[/\\]", re.IGNORECASE),
        re.compile(r"\.gitlab-ci\.yml$", re.IGNORECASE),
        re.compile(r"Jenkinsfile", re.IGNORECASE),
        re.compile(r"Dockerfile", re.IGNORECASE),
    ]

    PROD_KEYWORDS = {"prod", "production", "live", "mainnet", "master"}
    TEST_KEYWORDS = {"test", "mock", "dummy", "fake", "example", "sample", "sandbox", "placeholder", "demo"}

    @classmethod
    def is_test_file(cls, file_path: str) -> bool:
        """Determines if a file path belongs to a test, fixture, or mock directory."""
        if not file_path:
            return False
        for pat in cls.TEST_PATH_PATTERNS:
            if pat.search(file_path):
                return True
        return False

    @classmethod
    def is_documentation_file(cls, file_path: str) -> bool:
        """Determines if file is documentation or markdown."""
        if not file_path:
            return False
        for pat in cls.DOC_PATH_PATTERNS:
            if pat.search(file_path):
                return True
        return False

    @classmethod
    def is_cicd_file(cls, file_path: str) -> bool:
        """Determines if file is CI/CD configuration."""
        if not file_path:
            return False
        for pat in cls.CI_CD_PATH_PATTERNS:
            if pat.search(file_path):
                return True
        return False

    @classmethod
    def infer_environment(cls, file_path: str, context_line: str) -> SecretEnvironment:
        """Infers the execution environment (PRODUCTION, STAGING, DEVELOPMENT, TESTING) from context."""
        combined = f"{file_path} {context_line}".lower()

        if any(kw in combined for kw in cls.PROD_KEYWORDS):
            return SecretEnvironment.PRODUCTION
        elif "staging" in combined or "stage" in combined:
            return SecretEnvironment.STAGING
        elif "dev" in combined or "local" in combined:
            return SecretEnvironment.DEVELOPMENT
        elif any(kw in combined for kw in cls.TEST_KEYWORDS) or cls.is_test_file(file_path):
            return SecretEnvironment.TESTING

        return SecretEnvironment.UNKNOWN

    @classmethod
    def infer_privilege(cls, secret_type: SecretType, context_line: str) -> SecretPrivilege:
        """Infers potential privilege scope from secret type and surrounding code context."""
        line_lower = context_line.lower()

        if secret_type in (SecretType.DATABASE_CREDENTIAL, SecretType.DATABASE_URL):
            return SecretPrivilege.DATABASE
        elif secret_type == SecretType.CLOUD_CREDENTIAL:
            if "admin" in line_lower or "root" in line_lower:
                return SecretPrivilege.ADMINISTRATIVE
            return SecretPrivilege.CLOUD
        elif secret_type in (SecretType.SIGNING_KEY, SecretType.ENCRYPTION_KEY):
            return SecretPrivilege.SIGNING

        if "admin" in line_lower or "master" in line_lower or "root" in line_lower:
            return SecretPrivilege.ADMINISTRATIVE
        elif "write" in line_lower or "upload" in line_lower:
            return SecretPrivilege.WRITE
        elif "read" in line_lower or "fetch" in line_lower:
            return SecretPrivilege.READ

        return SecretPrivilege.UNKNOWN

    @classmethod
    def evaluate_context_confidence(
        self, candidate_val: str, context_key: str, file_path: str
    ) -> Tuple[Confidence, bool]:
        """Evaluates candidate confidence based on assignment context, test indicators, and variable names."""
        is_test = self.is_test_file(file_path)
        key_lower = context_key.lower()

        if any(kw in key_lower for kw in self.TEST_KEYWORDS) or any(kw in candidate_val.lower() for kw in self.TEST_KEYWORDS):
            return (Confidence.LOW, True)

        if is_test:
            return (Confidence.MEDIUM, True)

        # High confidence for explicit assignment keys
        high_conf_keys = {"api_key", "secret", "token", "password", "aws_secret_access_key", "private_key"}
        if any(hk in key_lower for hk in high_conf_keys):
            return (Confidence.HIGH, False)

        return (Confidence.MEDIUM, False)
