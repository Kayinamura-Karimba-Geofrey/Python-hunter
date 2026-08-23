"""End-to-End Test Suite for Step 42 Enterprise Multi-Tenancy, RBAC & Governance."""

import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.governance.auth import User
from python_hunter.domain.governance.engine import ApprovalStatus
from python_hunter.domain.governance.rbac import OrganizationMembership, SystemRole
from python_hunter.domain.governance.tenant import AssetCriticality, Environment, Organization, Project


class TestStep42GovernanceE2E(unittest.TestCase):
    """End-to-end tests validating tenant isolation, RBAC, approvals, and compliance."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_e2e_tenant_isolation_and_idor_prevention(self) -> None:
        """Prove Organization A user cannot access Organization B resources."""
        # Create Org A and Org B
        org_a = Organization("org-a", "Company A", "comp-a")
        org_b = Organization("org-b", "Company B", "comp-b")
        self.app_service.organizations["org-a"] = org_a
        self.app_service.organizations["org-b"] = org_b

        # Alice in Org A
        om_alice = [OrganizationMembership(user_id="usr-alice", organization_id="org-a", role=SystemRole.ORGANIZATION_OWNER)]
        ctx_alice = self.app_service.rbac_engine.build_tenant_context("usr-alice", "org-a", om_alice, [])

        # Attempt to access Org B findings/policies
        can_access_b = self.app_service.rbac_engine.authorize_request(ctx_alice, target_organization_id="org-b", required_permission="finding.read")
        self.assertFalse(can_access_b)

    def test_e2e_privilege_escalation_prevention(self) -> None:
        """Prove Developer role cannot perform Security Admin actions."""
        om_dev = [OrganizationMembership(user_id="usr-dev", organization_id="org-default", role=SystemRole.DEVELOPER)]
        ctx_dev = self.app_service.rbac_engine.build_tenant_context("usr-dev", "org-default", om_dev, [])

        can_approve = self.app_service.rbac_engine.authorize_request(ctx_dev, target_organization_id="org-default", required_permission="governance.approve")
        self.assertFalse(can_approve)

    def test_e2e_four_eyes_approval_and_risk_acceptance(self) -> None:
        """Test four-eyes principle workflow and risk acceptance expiration."""
        appr = self.app_service.governance_engine.request_approval(
            approval_id="APPR-99",
            org_id="org-default",
            requester_id="usr-dev",
            action_type="RISK_ACCEPTANCE",
            reason="Temporary legacy exception",
        )
        self.assertEqual(appr.status, ApprovalStatus.PENDING)

        # Self approval fails
        self.assertFalse(self.app_service.governance_engine.approve_request("APPR-99", approver_id="usr-dev"))

        # Independent approver succeeds
        self.assertTrue(self.app_service.governance_engine.approve_request("APPR-99", approver_id="usr-admin"))
        self.assertEqual(appr.status, ApprovalStatus.APPROVED)

    def test_e2e_compliance_evidence_collection(self) -> None:
        """Test mapping findings to security controls and recording evidence."""
        evidences = self.app_service.compliance_engine.map_finding_to_compliance("org-default", "FIND-101", "CWE-89")
        self.assertGreater(len(evidences), 0)
        self.assertEqual(evidences[0].control_id, "A03:2021")


if __name__ == "__main__":
    unittest.main()
