"""Security Knowledge Graph Engine Implementation synthesizing multi-domain findings into unified Attack Paths."""

import logging
from typing import Any, List, Optional, Tuple

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence, Severity
from python_hunter.domain.graph.analyzers import WholeProjectGraphBuilder
from python_hunter.domain.graph.models import AttackPath, SecurityGraph, WholeProjectRisk, SecurityNode, NodeType, SecurityEdge, EdgeType
from python_hunter.domain.correlation.correlation_engine import CorrelationEngine, FindingCluster
from python_hunter.domain.correlation.attack_path_engine import AttackPathEngine, WhatIfAnalyzer, AssetInventory

logger = logging.getLogger(__name__)


class SecurityKnowledgeGraphEngine:
    """Orchestrates whole-project security knowledge graph assembly, multi-domain correlation, attack path resolution, and risk calculation."""

    def __init__(self, mode: str = "balanced") -> None:
        self.mode = mode
        self.builder = WholeProjectGraphBuilder()
        self.correlation_engine = CorrelationEngine()
        self.attack_path_engine = AttackPathEngine()

    def analyze(self, documents: list[ASTDocument]) -> tuple[SecurityGraph, list[AttackPath], WholeProjectRisk]:
        """Builds unified SecurityKnowledgeGraph and computes whole-project risk."""
        graph = SecurityGraph()
        self.builder.build_graph(documents, graph)

        # Tracing attack paths via engine
        attack_paths = self.attack_path_engine.find_all_attack_paths(graph)

        if not attack_paths:
            # Fallback legacy edge resolution
            for edge in graph.edges:
                if edge.relationship in (EdgeType.FLOWS_TO, EdgeType.REACHES, EdgeType.EXPOSES):
                    attack_paths.append(
                        AttackPath(
                            id=f"ap-{edge.source_id}-{edge.target_id}",
                            title=f"Exploit Path: {edge.source_id} -> {edge.target_id}",
                            entry_point_id=edge.source_id,
                            target_asset_id=edge.target_id,
                            path_node_ids=[edge.source_id, edge.target_id],
                            risk_score=85.0,
                        )
                    )

        # Calculate Whole-Project Security Risk
        total_risk = max([n.risk_score for n in graph.nodes.values()], default=0.0)
        project_risk = WholeProjectRisk(
            overall_score=total_risk,
            exposure_score=60.0 if len(attack_paths) > 0 else 10.0,
            vulnerability_score=total_risk,
            dependency_score=10.0,
            malware_score=10.0,
            control_coverage_score=50.0,
            critical_attack_paths_count=len(attack_paths),
        )

        return graph, attack_paths, project_risk

    def synthesize_cross_domain_graph(
        self,
        sast_findings: List[Any] = None,
        sca_findings: List[Any] = None,
        secrets: List[Any] = None,
        infrastructure_resources: List[Any] = None,
        cicd_workflows: List[Any] = None,
    ) -> Tuple[SecurityGraph, List[AttackPath], List[FindingCluster]]:
        """Synthesizes SAST, SCA, Secrets, IaC, Containers, K8s, Cloud, and CI/CD into a unified correlated graph."""
        graph = SecurityGraph()

        # Root Repository node
        repo_node = SecurityNode(
            id="node:repo:root",
            type=NodeType.REPOSITORY,
            name="Python Hunter Workspace",
            risk_score=10.0,
            is_entry_point=False,
        )
        graph.add_node(repo_node)

        # 1. Process SAST & APIs
        sast_list = sast_findings or []
        for s in sast_list:
            fid = f"node:sast:{s.get('id', s.get('rule_id', 'unknown'))}"
            fn_node = SecurityNode(
                id=fid,
                type=NodeType.API_ENDPOINT if "API" in str(s.get("title", "")) or s.get("endpoint") else NodeType.FUNCTION,
                name=s.get("title") or s.get("rule_id", "Vulnerable Function"),
                file_path=s.get("file_path", ""),
                risk_score=s.get("risk_score", 75.0),
                is_entry_point=bool(s.get("endpoint") or "unauthenticated" in str(s.get("title", "")).lower()),
            )
            graph.add_node(fn_node)
            graph.add_edge(SecurityEdge(source_id="node:repo:root", target_id=fid, relationship=EdgeType.CONTAINS, evidence="Code Repository"))

        # 2. Process Dependencies (SCA)
        sca_list = sca_findings or []
        for dep in sca_list:
            dep_id = f"node:dep:{dep.get('package', dep.get('package_name', 'pkg'))}"
            dep_node = SecurityNode(
                id=dep_id,
                type=NodeType.DEPENDENCY,
                name=f"{dep.get('package', dep.get('package_name'))} ({dep.get('version', 'latest')})",
                risk_score=dep.get("risk_score", 70.0),
            )
            graph.add_node(dep_node)

            # Link SAST -> SCA if reachable
            for s in sast_list:
                s_id = f"node:sast:{s.get('id', s.get('rule_id', 'unknown'))}"
                graph.add_edge(SecurityEdge(source_id=s_id, target_id=dep_id, relationship=EdgeType.CALLS, evidence="Function uses vulnerable dependency"))

        # 3. Process Secrets
        secrets_list = secrets or []
        for sec in secrets_list:
            sec_id = f"node:secret:{sec.get('fingerprint', sec.get('rule_id', 'sec'))}"
            sec_node = SecurityNode(
                id=sec_id,
                type=NodeType.SECRET,
                name=sec.get("title", "Exposed Secret"),
                file_path=sec.get("file_path", ""),
                risk_score=90.0,
            )
            graph.add_node(sec_node)
            graph.add_edge(SecurityEdge(source_id="node:repo:root", target_id=sec_id, relationship=EdgeType.USES_SECRET, evidence="Hardcoded secret in repository"))

        # 4. Process Infrastructure / Containers / Cloud
        infra_list = infrastructure_resources or []
        for res in infra_list:
            rid = f"node:infra:{res.get('id', res.get('name', 'res'))}"
            r_type = str(res.get("type", "CLOUD_RESOURCE")).upper()

            if "DOCKER" in r_type or "CONTAINER" in r_type:
                ntype = NodeType.CONTAINER
            elif "KUBERNETES" in r_type or "K8S" in r_type:
                ntype = NodeType.KUBERNETES_RESOURCE
            elif "DATABASE" in r_type or "DB" in r_type:
                ntype = NodeType.DATABASE
            elif "STORAGE" in r_type or "S3" in r_type:
                ntype = NodeType.STORAGE
            elif "IAM" in r_type or "RBAC" in r_type or "ROLE" in r_type:
                ntype = NodeType.IDENTITY
            else:
                ntype = NodeType.CLOUD_RESOURCE

            res_node = SecurityNode(
                id=rid,
                type=ntype,
                name=res.get("name", "Infrastructure Resource"),
                file_path=res.get("file_path", ""),
                risk_score=80.0 if res.get("is_privileged") or res.get("is_publicly_exposed") else 40.0,
                is_entry_point=bool(res.get("is_publicly_exposed")),
                is_sensitive_asset=ntype in (NodeType.DATABASE, NodeType.STORAGE, NodeType.SECRET),
            )
            graph.add_node(res_node)

            # Link dependencies/containers -> cloud DB/Role
            for dep in sca_list:
                dep_id = f"node:dep:{dep.get('package', dep.get('package_name', 'pkg'))}"
                graph.add_edge(SecurityEdge(source_id=dep_id, target_id=rid, relationship=EdgeType.RUNS_IN, evidence="Dependency deployed in container"))

        # 5. Process CI/CD Workflows
        cicd_list = cicd_workflows or []
        for wf in cicd_list:
            wfid = f"node:cicd:{wf.get('name', 'workflow')}"
            wf_node = SecurityNode(
                id=wfid,
                type=NodeType.CICD_WORKFLOW,
                name=wf.get("name", "CI/CD Pipeline"),
                file_path=wf.get("file_path", ""),
                risk_score=75.0,
                is_entry_point=True,
            )
            graph.add_node(wf_node)
            graph.add_edge(SecurityEdge(source_id="node:repo:root", target_id=wfid, relationship=EdgeType.DEPLOYS, evidence="CI/CD deployment trigger"))

        # Build clusters & resolve attack paths
        all_raw_findings = sast_list + sca_list + secrets_list
        clusters = self.correlation_engine.correlate_findings(all_raw_findings, graph)
        attack_paths = self.attack_path_engine.find_all_attack_paths(graph)

        return graph, attack_paths, clusters
