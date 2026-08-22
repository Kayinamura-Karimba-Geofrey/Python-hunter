"""Unit tests for Step 38 — Unified Security Correlation & Attack Path Intelligence."""

import unittest
from python_hunter.domain.common.enums import Confidence, Severity, TrustBoundary, PrivilegeLevel
from python_hunter.domain.graph.models import SecurityGraph, NodeType, EdgeType, SecurityNode, SecurityEdge, AttackPath
from python_hunter.domain.graph.engine import SecurityKnowledgeGraphEngine
from python_hunter.domain.correlation.correlation_engine import CorrelationEngine, FindingCluster, RootCauseAnalyzer, CauseCategory
from python_hunter.domain.correlation.attack_path_engine import AttackPathEngine, WhatIfAnalyzer, AssetInventory
from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestSecurityCorrelationAndAttackPaths(unittest.TestCase):
    """Verifies cross-domain correlation, attack path traversal, evidence tracking, and what-if simulation."""

    def setUp(self):
        self.graph_engine = SecurityKnowledgeGraphEngine()
        self.correlation_engine = CorrelationEngine()
        self.attack_path_engine = AttackPathEngine()
        self.app_service = SecurityApplicationService()

    def test_full_cross_domain_attack_path_chain(self):
        """Tests complete chain: Internet -> Public API -> Vulnerable Fn -> Vulnerable Dep -> Container -> K8s -> Cloud Role -> DB."""
        graph = SecurityGraph()

        # 1. Entry Point Node (Internet / API Endpoint)
        n_api = SecurityNode(id="node:api", type=NodeType.API_ENDPOINT, name="GET /api/v1/users/{id}", risk_score=80.0, is_entry_point=True)
        # 2. Vulnerable Code Function
        n_fn = SecurityNode(id="node:fn", type=NodeType.FUNCTION, name="get_user_by_id", file_path="src/db.py", risk_score=90.0)
        # 3. Vulnerable Dependency
        n_dep = SecurityNode(id="node:dep", type=NodeType.DEPENDENCY, name="urllib3 (1.26.4)", risk_score=75.0)
        # 4. Container Workload
        n_cnt = SecurityNode(id="node:container", type=NodeType.CONTAINER, name="auth-service-container", risk_score=85.0)
        # 5. Kubernetes Service Account
        n_k8s = SecurityNode(id="node:k8s", type=NodeType.KUBERNETES_RESOURCE, name="auth-sa", risk_score=70.0)
        # 6. Cloud IAM Role
        n_iam = SecurityNode(id="node:iam", type=NodeType.IDENTITY, name="arn:aws:iam::123456:role/AuthRole", risk_score=85.0)
        # 7. Sensitive Target Database
        n_db = SecurityNode(id="node:db", type=NodeType.DATABASE, name="ProdUserPostgresDB", risk_score=95.0, is_sensitive_asset=True)

        for n in [n_api, n_fn, n_dep, n_cnt, n_k8s, n_iam, n_db]:
            graph.add_node(n)

        # Edges
        graph.add_edge(SecurityEdge(source_id="node:api", target_id="node:fn", relationship=EdgeType.CALLS, evidence="Route dispatches to fn"))
        graph.add_edge(SecurityEdge(source_id="node:fn", target_id="node:dep", relationship=EdgeType.DEPENDS_ON, evidence="Function imports vulnerable package"))
        graph.add_edge(SecurityEdge(source_id="node:dep", target_id="node:container", relationship=EdgeType.RUNS_IN, evidence="Dependency deployed in container"))
        graph.add_edge(SecurityEdge(source_id="node:container", target_id="node:k8s", relationship=EdgeType.GRANTS, evidence="Pod uses service account"))
        graph.add_edge(SecurityEdge(source_id="node:k8s", target_id="node:iam", relationship=EdgeType.ASSUMES_ROLE, evidence="Service account assumes IAM role"))
        graph.add_edge(SecurityEdge(source_id="node:iam", target_id="node:db", relationship=EdgeType.CONNECTS_TO, evidence="Role grants access to database"))

        attack_paths = self.attack_path_engine.find_all_attack_paths(graph)

        self.assertGreaterEqual(len(attack_paths), 1)
        primary_path = attack_paths[0]
        self.assertEqual(primary_path.entry_point_id, "node:api")
        self.assertEqual(primary_path.target_asset_id, "node:db")
        self.assertIn("node:fn", primary_path.path_node_ids)
        self.assertIn("node:iam", primary_path.path_node_ids)
        self.assertGreaterEqual(primary_path.risk_score, 85.0)
        self.assertEqual(primary_path.severity, Severity.CRITICAL)

    def test_false_correlation_prevention(self):
        """Verifies that unrelated security findings in disconnected modules are NOT correlated into an attack path."""
        graph = SecurityGraph()

        # Unrelated Node A
        n_a = SecurityNode(id="node:unrelated_a", type=NodeType.FUNCTION, name="helper_a", file_path="src/a.py", is_entry_point=True)
        # Unrelated Node B (no edges connecting A to B)
        n_b = SecurityNode(id="node:unrelated_b", type=NodeType.DATABASE, name="isolated_db", file_path="src/b.py", is_sensitive_asset=True)

        graph.add_node(n_a)
        graph.add_node(n_b)

        paths = self.attack_path_engine.find_all_attack_paths(graph)
        self.assertEqual(len(paths), 0)

    def test_what_if_remediation_simulation(self):
        """Verifies that remediating an entry point node breaks the attack path and reduces risk."""
        graph = SecurityGraph()
        n_api = SecurityNode(id="node:api", type=NodeType.API_ENDPOINT, name="GET /api/v1/users/{id}", risk_score=80.0, is_entry_point=True)
        n_db = SecurityNode(id="node:db", type=NodeType.DATABASE, name="ProdDB", risk_score=95.0, is_sensitive_asset=True)

        graph.add_node(n_api)
        graph.add_node(n_db)
        graph.add_edge(SecurityEdge(source_id="node:api", target_id="node:db", relationship=EdgeType.CONNECTS_TO, evidence="Direct connection"))

        # Simulate removing the entry point API
        sim_res = WhatIfAnalyzer.simulate_remediation(graph, self.attack_path_engine, ["node:api"])

        self.assertEqual(sim_res["before_attack_paths_count"], 1)
        self.assertEqual(sim_res["after_attack_paths_count"], 0)
        self.assertEqual(sim_res["broken_attack_paths_count"], 1)
        self.assertGreater(sim_res["risk_reduction"], 0.0)

    def test_finding_clustering_and_root_cause(self):
        """Verifies grouping of duplicate findings and root cause classification."""
        findings = [
            {"id": "f1", "title": "Hardcoded Secret", "rule_id": "PYH-SECRET-001", "file_path": "config.py", "line_number": 10},
            {"id": "f2", "title": "Hardcoded Secret", "rule_id": "PYH-SECRET-001", "file_path": "config.py", "line_number": 10}, # Dup
        ]
        clusters = self.correlation_engine.correlate_findings(findings, SecurityGraph())

        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].primary_finding_id, "f1")
        self.assertEqual(len(clusters[0].member_finding_ids), 2)

        role = RootCauseAnalyzer.analyze_finding_role(findings[0], SecurityGraph())
        self.assertEqual(role, CauseCategory.ROOT_CAUSE)

    def test_application_service_what_if(self):
        """Verifies What-If simulation service method."""
        res = self.app_service.simulate_remediation(".", ["find-101"])
        self.assertIn("broken_attack_paths_count", res)
        self.assertIn("risk_reduction", res)


if __name__ == "__main__":
    unittest.main()
