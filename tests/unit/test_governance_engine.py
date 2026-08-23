"""Unit tests for Step 42 Enterprise Multi-Tenancy & Security Governance."""

import unittest

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.governance.auth import ApiToken, Session, User, UserStatus
from python_hunter.domain.governance.compliance import ComplianceEngine, ComplianceStatus
from python_hunter.domain.governance.engine import ApprovalStatus, GovernanceEngine
from python_hunter.domain.governance.rbac import OrganizationMembership, RBACEngine, SystemRole, TeamMembership
from python_hunter.domain.governance.tenant import AssetCriticality, Environment, Organization, Project, TenantContext


class TestGovernanceEngineUnit(unittest.TestCase):
    """Unit tests for multi-tenancy, RBAC, approvals, and governance."""

    def test_user_password_security(self) -> None:
        raw_pwd = "SecretPassword123!"
        hashed = User.hash_password(raw_pwd)
        u = User(user_id="u1", email="test@pyh.io", display_name="Test", password_hash=hashed)

        self.assertTrue(u.verify_password(raw_pwd))
        self.assertFalse(u.verify_password("WrongPassword"))
        self.assertNotIn(raw_pwd, hashed)

    def test_tenant_isolation_and_rbac(self) -> None:
        engine = RBACEngine()
        om_a = [OrganizationMembership(user_id="u-alice", organization_id="org-a", role=SystemRole.DEVELOPER)]
        om_b = [OrganizationMembership(user_id="u-bob", organization_id="org-b", role=SystemRole.ORGANIZATION_OWNER)]

        ctx_alice = engine.build_tenant_context("u-alice", "org-a", om_a, [])
        ctx_bob = engine.build_tenant_context("u-bob", "org-b", om_b, [])

        # Alice cannot access Org B
        self.assertFalse(engine.authorize_request(ctx_alice, target_organization_id="org-b", required_permission="finding.read"))

        # Alice (Developer) cannot manage users in Org A
        self.assertFalse(engine.authorize_request(ctx_alice, target_organization_id="org-a", required_permission="user.manage"))

        # Bob (Owner) can manage users in Org B
        self.assertTrue(engine.authorize_request(ctx_bob, target_organization_id="org-b", required_permission="user.manage"))

    def test_four_eyes_approval_principle(self) -> None:
        gov = GovernanceEngine()
        appr = gov.request_approval("appr-1", "org-a", requester_id="usr-requester", action_type="RISK_ACCEPTANCE", reason="Legacy system")

        # Requester cannot approve their own request
        self.assertFalse(gov.approve_request("appr-1", approver_id="usr-requester"))
        self.assertEqual(appr.status, ApprovalStatus.PENDING)

        # Independent approver succeeds
        self.assertTrue(gov.approve_request("appr-1", approver_id="usr-approver"))
        self.assertEqual(appr.status, ApprovalStatus.APPROVED)

    def test_risk_acceptance_expiration(self) -> None:
        gov = GovernanceEngine()
        ra = gov.record_risk_acceptance("ra-1", "org-a", "FIND-101", "usr-1", "Business need", Severity.HIGH, days=-1)
        self.assertTrue(ra.is_expired)
        self.assertIsNone(gov.evaluate_active_risk_acceptance("FIND-101"))

    def test_compliance_control_mapping(self) -> None:
        comp = ComplianceEngine()
        evidence = comp.map_finding_to_compliance("org-a", "FIND-SQLI", "CWE-89")
        self.assertGreater(len(evidence), 0)
        self.assertEqual(evidence[0].status, ComplianceStatus.FAIL)


if __name__ == "__main__":
    unittest.main()
