"""Kubernetes and Helm static manifest adapter."""

import os
from typing import Any, Dict, List, Optional
from python_hunter.domain.infrastructure.models import (
    ContainerImage,
    IAMPolicy,
    IAMPermission,
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)
from python_hunter.domain.infrastructure.yaml_parser import safe_yaml_load, safe_yaml_load_all
from python_hunter.infrastructure.iac.registry import InfrastructureAdapter


class KubernetesAdapter(InfrastructureAdapter):
    """Parses Kubernetes YAML manifests and Helm charts statically without executing templates."""

    @property
    def adapter_name(self) -> str:
        return "KubernetesAdapter"

    def detect(self, file_path: str, content: str) -> bool:
        fname = os.path.basename(file_path).lower()
        if fname.endswith((".yaml", ".yml")):
            if "apiVersion:" in content and "kind:" in content:
                return True
            if "Chart.yaml" in fname or "values.yaml" in fname or "/templates/" in file_path:
                return True
        return False

    def parse_and_build_ir(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        fname = os.path.basename(file_path).lower()
        if "chart.yaml" in fname or "values.yaml" in fname or "/templates/" in file_path:
            self._parse_helm(file_path, content, ir)
            return

        # Parse multi-document YAML
        try:
            docs = safe_yaml_load_all(content)
        except Exception:
            return

        for doc in docs:
            if not isinstance(doc, dict) or "kind" not in doc:
                continue
            self._parse_k8s_doc(file_path, doc, ir)

    def _parse_helm(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        try:
            doc = safe_yaml_load(content)
        except Exception:
            doc = {}

        res = InfrastructureResource(
            id=f"helm::{file_path}",
            name=os.path.basename(file_path),
            type=InfrastructureResourceType.HELM_CHART,
            provider="Helm",
            file_path=file_path,
            properties={"raw_yaml": doc if isinstance(doc, dict) else {}},
        )
        ir.resources.append(res)
        ir.graph.add_resource(res)
        ir.helm_charts.append({"file_path": file_path, "resource": res})

    def _parse_k8s_doc(self, file_path: str, doc: Dict[str, Any], ir: InfrastructureIR) -> None:
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace", "default")

        res_type = InfrastructureResourceType.KUBERNETES_WORKLOAD
        if kind in ("Service",):
            res_type = InfrastructureResourceType.KUBERNETES_SERVICE
        elif kind in ("Ingress",):
            res_type = InfrastructureResourceType.KUBERNETES_INGRESS
        elif kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            res_type = InfrastructureResourceType.KUBERNETES_RBAC
        elif kind in ("Secret",):
            res_type = InfrastructureResourceType.KUBERNETES_SECRET
        elif kind in ("ConfigMap",):
            res_type = InfrastructureResourceType.KUBERNETES_CONFIG

        is_privileged = False
        runs_as_root = True  # K8s defaults to root unless specified
        images = []
        exposed_ports = []
        is_public = False
        iam_policies = []

        # Extract workload securityContext & containers
        spec = doc.get("spec", {})
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            spec = spec.get("template", {}).get("spec", {})

        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet"):
            pod_sec = spec.get("securityContext", {})
            if pod_sec.get("runAsNonRoot") is True or pod_sec.get("runAsUser", 0) > 0:
                runs_as_root = False

            containers = spec.get("containers", [])
            for container in containers:
                c_img = container.get("image", "")
                if c_img:
                    is_latest = c_img.endswith(":latest") or ":" not in c_img
                    is_pinned = "@sha256:" in c_img
                    images.append(
                        ContainerImage(
                            raw_reference=c_img,
                            is_pinned_by_digest=is_pinned,
                            is_latest_or_unpinned=is_latest,
                        )
                    )

                c_sec = container.get("securityContext", {})
                if c_sec.get("privileged") is True:
                    is_privileged = True
                if c_sec.get("runAsNonRoot") is True or c_sec.get("runAsUser", 0) > 0:
                    runs_as_root = False
                elif c_sec.get("runAsNonRoot") is False or c_sec.get("runAsUser") == 0:
                    runs_as_root = True

        # Extract Service / Ingress exposure
        if kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in ("LoadBalancer", "NodePort"):
                is_public = True
            for port in spec.get("ports", []):
                if isinstance(port, dict) and "port" in port:
                    exposed_ports.append(port["port"])
        elif kind == "Ingress":
            is_public = True

        # Extract RBAC permissions
        if kind in ("Role", "ClusterRole"):
            rules = doc.get("rules", [])
            permissions = []
            is_admin = False
            for rule in rules:
                api_groups = rule.get("apiGroups", [])
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                has_wildcard_verb = "*" in verbs
                has_wildcard_res = "*" in resources
                if has_wildcard_verb and has_wildcard_res:
                    is_admin = True

                permissions.append(
                    IAMPermission(
                        effect="Allow",
                        actions=verbs,
                        resources=resources,
                        has_wildcard_action=has_wildcard_verb,
                        has_wildcard_resource=has_wildcard_res,
                    )
                )

            iam_policies.append(
                IAMPolicy(
                    name=name,
                    principal_or_role=kind,
                    permissions=permissions,
                    is_admin=is_admin,
                )
            )

        res = InfrastructureResource(
            id=f"k8s::{namespace}::{kind}::{name}",
            name=f"{kind}/{name}",
            type=res_type,
            provider="Kubernetes",
            file_path=file_path,
            properties={
                "kind": kind,
                "namespace": namespace,
                "spec": spec,
                "hostNetwork": spec.get("hostNetwork", False),
                "hostPID": spec.get("hostPID", False),
            },
            container_images=images,
            iam_policies=iam_policies,
            exposed_ports=exposed_ports,
            is_publicly_exposed=is_public,
            is_privileged=is_privileged,
            runs_as_root=runs_as_root,
        )

        ir.resources.append(res)
        ir.graph.add_resource(res)
        ir.kubernetes_manifests.append({"file_path": file_path, "kind": kind, "name": name, "resource": res})
