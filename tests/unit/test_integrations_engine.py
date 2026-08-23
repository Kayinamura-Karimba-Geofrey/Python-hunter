"""Unit tests for Step 43 Enterprise Integrations & Security Ecosystem."""

import unittest

from python_hunter.domain.integrations.credentials import CredentialManager
from python_hunter.domain.integrations.engine import IntegrationCircuitBreaker, IntegrationEngine
from python_hunter.domain.integrations.models import Integration, IntegrationProviderType, IntegrationStatus
from python_hunter.domain.integrations.providers import JiraProvider, SlackProvider, WebhookProvider


class TestIntegrationsEngineUnit(unittest.TestCase):
    """Unit tests for credentials, circuit breaker, webhook signing, and providers."""

    def test_credential_encryption_and_tenant_isolation(self) -> None:
        mgr = CredentialManager(master_key="test_master_key_32bytes")
        meta = mgr.store_credential(
            credential_id="cred-jira-1",
            organization_id="org-a",
            integration_id="int-jira-1",
            name="Jira Token",
            secret_payload={"api_token": "secret_jira_api_token_123"},
        )

        # Retrieve secret within org-a succeeds
        secret = mgr.retrieve_secret("cred-jira-1", requesting_org_id="org-a")
        self.assertEqual(secret["api_token"], "secret_jira_api_token_123")

        # Cross-tenant retrieval from org-b fails
        with self.assertRaises(PermissionError):
            mgr.retrieve_secret("cred-jira-1", requesting_org_id="org-b")

    def test_outbound_webhook_hmac_signature(self) -> None:
        provider = WebhookProvider(signing_secret="my_webhook_signing_secret")
        payload = b'{"event": "finding.created", "finding_id": "FIND-101"}'
        sig = provider.generate_signature(payload)

        self.assertTrue(sig.startswith("sha256="))
        self.assertGreater(len(sig), 40)

    def test_circuit_breaker_failure_threshold(self) -> None:
        cb = IntegrationCircuitBreaker(failure_threshold=2, recovery_time_seconds=60)
        self.assertTrue(cb.can_execute())

        cb.record_failure()
        self.assertEqual(cb.state, "CLOSED")

        cb.record_failure()  # Second failure -> Trips circuit breaker
        self.assertEqual(cb.state, "OPEN")
        self.assertFalse(cb.can_execute())

    def test_jira_issue_deduplication(self) -> None:
        jira = JiraProvider()
        jira.connect({"jira_url": "https://jira.enterprise.com", "api_token": "token"})

        res1 = jira.send({"finding_id": "FIND-SQLI-01"})
        key1 = jira.issue_map.get("FIND-SQLI-01")

        res2 = jira.send({"finding_id": "FIND-SQLI-01"})
        key2 = jira.issue_map.get("FIND-SQLI-01")

        self.assertTrue(res1)
        self.assertTrue(res2)
        self.assertEqual(key1, key2)  # Same correlation issue key retained


if __name__ == "__main__":
    unittest.main()
