"""End-to-End Test Suite for Step 43 Enterprise Integrations & Security Ecosystem."""

import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.integrations.models import Integration, IntegrationProviderType, IntegrationStatus


class TestStep43IntegrationsE2E(unittest.TestCase):
    """End-to-end tests validating enterprise integrations, credential security, and tenant boundaries."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_e2e_integration_registration_and_dispatch(self) -> None:
        """Test registering outbound webhook integration and dispatching signed events."""
        integ = Integration(
            integration_id="int-webhook-prod",
            organization_id="org-default",
            provider=IntegrationProviderType.WEBHOOK,
            name="Production Outbound Webhook",
        )
        self.app_service.integration_engine.register_integration(integ)

        dispatched = self.app_service.integration_engine.dispatch_event(
            integration_id="int-webhook-prod",
            requesting_org_id="org-default",
            payload={"event": "incident.created", "incident_id": "INC-101"},
        )
        self.assertTrue(dispatched)

    def test_e2e_cross_tenant_integration_dispatch_blocked(self) -> None:
        """Prove Organization A cannot dispatch events via Organization B's integration."""
        integ_b = Integration(
            integration_id="int-jira-org-b",
            organization_id="org-b",
            provider=IntegrationProviderType.JIRA,
            name="Org B Jira",
        )
        self.app_service.integration_engine.register_integration(integ_b)

        with self.assertRaises(PermissionError):
            self.app_service.integration_engine.dispatch_event(
                integration_id="int-jira-org-b",
                requesting_org_id="org-default",
                payload={"finding_id": "FIND-101"},
            )

    def test_e2e_credential_rotation_and_retrieval(self) -> None:
        """Test storing encrypted credentials and secret rotation."""
        meta = self.app_service.integration_engine.credential_manager.store_credential(
            credential_id="cred-slack-key",
            organization_id="org-default",
            integration_id="int-slack-1",
            name="Slack Webhook URL",
            secret_payload={"url": "https://hooks.slack.com/services/111/222/333"},
        )
        self.assertEqual(meta.organization_id, "org-default")

        # Rotate secret
        rotated = self.app_service.integration_engine.credential_manager.rotate_credential(
            credential_id="cred-slack-key",
            requesting_org_id="org-default",
            new_secret_payload={"url": "https://hooks.slack.com/services/444/555/666"},
        )
        self.assertTrue(rotated)

        secret = self.app_service.integration_engine.credential_manager.retrieve_secret(
            "cred-slack-key", requesting_org_id="org-default"
        )
        self.assertEqual(secret["url"], "https://hooks.slack.com/services/444/555/666")


if __name__ == "__main__":
    unittest.main()
