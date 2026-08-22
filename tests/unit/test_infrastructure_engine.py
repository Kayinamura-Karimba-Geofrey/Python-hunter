"""Unit tests for Step 37 Infrastructure Security Engine."""

import os
import unittest
from python_hunter.domain.infrastructure.models import InfrastructureIR
from python_hunter.infrastructure.iac.docker_adapter import DockerAdapter
from python_hunter.infrastructure.iac.k8s_adapter import KubernetesAdapter
from python_hunter.infrastructure.iac.terraform_adapter import TerraformAdapter
from python_hunter.infrastructure.iac.cicd_adapter import CICDAdapter
from python_hunter.domain.infrastructure.rules_engine import InfrastructureSecurityRuleEngine
from python_hunter.domain.infrastructure.graph_engine import CrossLayerGraphEngine


class TestInfrastructureSecurityEngine(unittest.TestCase):

    def setUp(self):
        self.docker_adapter = DockerAdapter()
        self.k8s_adapter = KubernetesAdapter()
        self.tf_adapter = TerraformAdapter()
        self.cicd_adapter = CICDAdapter()
        self.rule_engine = InfrastructureSecurityRuleEngine()
        self.graph_engine = CrossLayerGraphEngine()

    def test_dockerfile_parsing_and_security_rules(self):
        dockerfile_content = """
        FROM python:latest
        ENV API_SECRET="super_secret_key_123"
        EXPOSE 8080
        CMD ["python", "app.py"]
        """
        ir = InfrastructureIR(scan_path="/tmp")
        self.docker_adapter.parse_and_build_ir("Dockerfile", dockerfile_content, ir)

        self.assertEqual(len(ir.resources), 1)
        res = ir.resources[0]
        self.assertTrue(res.runs_as_root)
        self.assertEqual(res.exposed_ports, [8080])

        findings = self.rule_engine.evaluate_ir(ir)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-IAC-001", rule_ids)  # Runs as root
        self.assertIn("PYH-IAC-002", rule_ids)  # Unpinned base image
        self.assertIn("PYH-IAC-003", rule_ids)  # Hard-coded secret in ENV

    def test_docker_compose_privileged_and_ports(self):
        compose_content = """
        version: '3.8'
        services:
          web:
            image: nginx:latest
            privileged: true
            ports:
              - "0.0.0.0:2375:2375"
            network_mode: host
        """
        ir = InfrastructureIR(scan_path="/tmp")
        self.docker_adapter.parse_and_build_ir("docker-compose.yml", compose_content, ir)

        findings = self.rule_engine.evaluate_ir(ir)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-IAC-004", rule_ids)  # Privileged
        self.assertIn("PYH-IAC-005", rule_ids)  # Host network
        self.assertIn("PYH-IAC-006", rule_ids)  # Exposed admin port

    def test_kubernetes_manifest_rbac_and_privileges(self):
        k8s_content = """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: api-deployment
          namespace: prod
        spec:
          template:
            spec:
              hostNetwork: true
              containers:
              - name: api
                image: myapi:1.0
                securityContext:
                  privileged: true
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: super-admin
        rules:
        - apiGroups: ["*"]
          resources: ["*"]
          verbs: ["*"]
        """
        ir = InfrastructureIR(scan_path="/tmp")
        self.k8s_adapter.parse_and_build_ir("deployment.yaml", k8s_content, ir)

        findings = self.rule_engine.evaluate_ir(ir)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-IAC-007", rule_ids)  # K8s privileged
        self.assertIn("PYH-IAC-009", rule_ids)  # Host network
        self.assertIn("PYH-IAC-010", rule_ids)  # Wildcard RBAC

    def test_terraform_cloud_resources_and_public_storage(self):
        tf_content = """
        resource "aws_s3_bucket" "data_bucket" {
          bucket = "my-public-bucket"
          acl    = "public-read"
        }

        resource "aws_db_instance" "db" {
          allocated_storage = 20
          publicly_accessible = true
          encrypted = false
        }
        """
        ir = InfrastructureIR(scan_path="/tmp")
        self.tf_adapter.parse_and_build_ir("main.tf", tf_content, ir)

        findings = self.rule_engine.evaluate_ir(ir)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-IAC-011", rule_ids)  # Public storage
        self.assertIn("PYH-IAC-012", rule_ids)  # Public DB
        self.assertIn("PYH-IAC-013", rule_ids)  # Missing encryption

    def test_github_actions_ci_cd_security(self):
        gh_content = """
        name: Build
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
            - uses: actions/checkout@v2
            - name: Run injection
              run: echo "User title: ${{ github.event.issue.title }}"
        """
        ir = InfrastructureIR(scan_path="/tmp")
        self.cicd_adapter.parse_and_build_ir(".github/workflows/ci.yml", gh_content, ir)

        findings = self.rule_engine.evaluate_ir(ir)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-IAC-015", rule_ids)  # Unpinned action
        self.assertIn("PYH-IAC-016", rule_ids)  # pull_request_target
        self.assertIn("PYH-IAC-017", rule_ids)  # Command injection

    def test_cross_layer_attack_path(self):
        ir = InfrastructureIR(scan_path="/tmp")

        # Add public ingress
        self.k8s_adapter.parse_and_build_ir(
            "ingress.yaml",
            """
            apiVersion: networking.k8s.io/v1
            kind: Ingress
            metadata:
              name: public-api-ingress
            spec:
              rules: []
            """,
            ir,
        )

        # Add privileged pod connected to DB
        self.k8s_adapter.parse_and_build_ir(
            "deployment.yaml",
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: api-service
            spec:
              template:
                spec:
                  containers:
                  - name: web
                    image: web:latest
                    securityContext:
                      privileged: true
            """,
            ir,
        )

        self.tf_adapter.parse_and_build_ir(
            "db.tf",
            """
            resource "aws_db_instance" "prod_db" {
              allocated_storage = 100
            }
            """,
            ir,
        )

        cross_graph = self.graph_engine.build_cross_layer_graph(ir)
        paths = self.graph_engine.trace_cross_layer_attack_paths(cross_graph)
        self.assertGreaterEqual(len(paths), 1)
        self.assertIn("Cross-Layer Attack Path", paths[0]["title"])


if __name__ == "__main__":
    unittest.main()
