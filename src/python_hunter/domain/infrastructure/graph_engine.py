"""Cross-layer graph construction and attack path extension for Infrastructure, Container, Cloud, and App Code."""

from typing import Any, Dict, List, Optional
from python_hunter.domain.infrastructure.models import (
    InfrastructureGraph,
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)


class CrossLayerGraphEngine:
    """Links Application Code, Dependencies, Secrets, Docker Containers, Kubernetes, and Cloud IAM into a single unified Attack-Path graph."""

    def build_cross_layer_graph(self, ir: InfrastructureIR) -> InfrastructureGraph:
        graph = ir.graph

        # Link Containers / Pods -> Services -> Ingress / Load Balancers
        workloads = [r for r in ir.resources if r.type in (InfrastructureResourceType.DOCKERFILE, InfrastructureResourceType.DOCKER_COMPOSE, InfrastructureResourceType.KUBERNETES_WORKLOAD)]
        services = [r for r in ir.resources if r.type in (InfrastructureResourceType.KUBERNETES_SERVICE, InfrastructureResourceType.CLOUD_NETWORK)]
        ingresses = [r for r in ir.resources if r.type in (InfrastructureResourceType.KUBERNETES_INGRESS, InfrastructureResourceType.CLOUD_NETWORK) if r.is_publicly_exposed]
        cloud_dbs = [r for r in ir.resources if r.type in (InfrastructureResourceType.CLOUD_DATABASE, InfrastructureResourceType.CLOUD_STORAGE)]
        iam_roles = [r for r in ir.resources if r.type in (InfrastructureResourceType.KUBERNETES_RBAC, InfrastructureResourceType.CLOUD_IAM)]

        # Internet -> Ingress / Public Resources
        for pub in ingresses + [r for r in ir.resources if r.is_publicly_exposed and r not in ingresses]:
            graph.add_edge("Internet", pub.id, "INTERNET_EXPOSED")
            # Ingress -> Service / Workload
            for svc in services:
                graph.add_edge(pub.id, svc.id, "ROUTES_TO")
            for wrk in workloads:
                graph.add_edge(pub.id, wrk.id, "TARGETS_WORKLOAD")

        # Service -> Workload
        for svc in services:
            for wrk in workloads:
                graph.add_edge(svc.id, wrk.id, "TARGETS_POD")

        # Workload -> Cloud DB / Storage
        for wrk in workloads:
            for db in cloud_dbs:
                graph.add_edge(wrk.id, db.id, "CONNECTS_TO_DATASTORE")

        # Workload -> IAM Role
        for wrk in workloads:
            for iam in iam_roles:
                graph.add_edge(wrk.id, iam.id, "ASSUMES_ROLE")

        return graph

    def trace_cross_layer_attack_paths(self, graph: InfrastructureGraph) -> List[Dict[str, Any]]:
        """Identifies full cross-layer attack chains from Internet -> Public Exposure -> Workload -> IAM -> Cloud Datastore."""
        attack_paths: List[Dict[str, Any]] = []

        # Find publicly exposed entry points
        public_resources = [r for r in graph.resources.values() if r.is_publicly_exposed]

        for pub in public_resources:
            # Look for connected workloads
            connected_edges = [e for e in graph.edges if e.source_id == pub.id or e.target_id == pub.id]
            for edge in connected_edges:
                target_res = graph.resources.get(edge.target_id)
                if not target_res:
                    continue

                # Check if workload is privileged or runs as root
                if target_res.is_privileged or target_res.runs_as_root:
                    # Check for IAM roles or connected databases
                    workload_edges = [e for e in graph.edges if e.source_id == target_res.id]
                    for w_edge in workload_edges:
                        dst_res = graph.resources.get(w_edge.target_id)
                        if dst_res and (dst_res.type in (InfrastructureResourceType.CLOUD_DATABASE, InfrastructureResourceType.CLOUD_STORAGE, InfrastructureResourceType.CLOUD_IAM)):
                            attack_paths.append(
                                {
                                    "title": f"Cross-Layer Attack Path: {pub.name} -> {target_res.name} -> {dst_res.name}",
                                    "severity": "CRITICAL",
                                    "chain": [
                                        {"node": "Internet", "type": "ENTRY_POINT"},
                                        {"node": pub.name, "type": "PUBLIC_EXPOSURE", "file": pub.file_path},
                                        {"node": target_res.name, "type": "CONTAINER_WORKLOAD", "file": target_res.file_path, "privileged": target_res.is_privileged},
                                        {"node": dst_res.name, "type": "CLOUD_RESOURCE", "file": dst_res.file_path},
                                    ],
                                    "description": f"An attacker on the Internet can access {pub.name}, exploit container {target_res.name}, and escalate privileges to access {dst_res.name}.",
                                }
                            )

        return attack_paths
