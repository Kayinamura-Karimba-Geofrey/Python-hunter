"""Infrastructure security rules engine for Docker, Kubernetes, Terraform, and CI/CD."""

from typing import Any, Dict, List
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.infrastructure.models import (
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)
from python_hunter.domain.findings.finding import Finding


class InfrastructureSecurityRuleEngine:
    """Evaluates static security rules against the unified Infrastructure IR."""

    def evaluate_ir(self, ir: InfrastructureIR) -> List[Finding]:
        findings: List[Finding] = []
        for resource in ir.resources:
            if resource.type == InfrastructureResourceType.DOCKERFILE:
                findings.extend(self._evaluate_dockerfile(resource))
            elif resource.type == InfrastructureResourceType.DOCKER_COMPOSE:
                findings.extend(self._evaluate_docker_compose(resource))
            elif resource.type in (
                InfrastructureResourceType.KUBERNETES_WORKLOAD,
                InfrastructureResourceType.KUBERNETES_SERVICE,
                InfrastructureResourceType.KUBERNETES_RBAC,
            ):
                findings.extend(self._evaluate_kubernetes(resource))
            elif resource.type in (
                InfrastructureResourceType.TERRAFORM_RESOURCE,
                InfrastructureResourceType.CLOUD_STORAGE,
                InfrastructureResourceType.CLOUD_DATABASE,
                InfrastructureResourceType.CLOUD_NETWORK,
                InfrastructureResourceType.CLOUD_IAM,
            ):
                findings.extend(self._evaluate_terraform(resource))
            elif resource.type == InfrastructureResourceType.GITHUB_ACTION_WORKFLOW:
                findings.extend(self._evaluate_cicd(resource))
        return findings

    def _evaluate_dockerfile(self, res: InfrastructureResource) -> List[Finding]:
        findings = []
        if res.runs_as_root:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIGURATION,
                    title="Dockerfile Runs As Root",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence="Dockerfile does not specify a non-root USER instruction.",
                    description="Container process runs as root, increasing privilege escalation risk.",
                    remediation="Add 'USER nonroot' or specify a non-zero numeric UID before CMD/ENTRYPOINT.",
                )
            )

        for img in res.container_images:
            if img.is_latest_or_unpinned and not img.is_pinned_by_digest:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-002",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        title="Unpinned Docker Base Image",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Base image reference '{img.raw_reference}' uses mutable tag or latest.",
                        description="Base images using mutable tags lead to non-reproducible and unstable security builds.",
                        remediation="Pin base images by exact version tag or sha256 digest reference.",
                    )
                )

        envs = res.properties.get("envs", {})
        args = res.properties.get("args", {})
        for k, v in {**envs, **args}.items():
            if any(sec_kw in k.lower() for sec_kw in ("password", "secret", "api_key", "token", "private_key")):
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-003",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.SECRET_LEAK,
                        title="Hard-coded Secret in Dockerfile ENV/ARG",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Secret variable '{k}' set in Dockerfile ENV/ARG.",
                        description="Embedding secrets in Dockerfiles bakes sensitive material directly into image layers.",
                        remediation="Pass secrets at runtime using container environment variables or secret mounts.",
                    )
                )
        return findings

    def _evaluate_docker_compose(self, res: InfrastructureResource) -> List[Finding]:
        findings = []
        if res.is_privileged:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-004",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIGURATION,
                    title="Docker Compose Privileged Container",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Service '{res.name}' has 'privileged: true'.",
                    description="Privileged containers gain full root access to host device nodes.",
                    remediation="Set 'privileged: false' and grant only required specific Linux capabilities.",
                )
            )

        if res.properties.get("network_mode") == "host":
            findings.append(
                Finding(
                    rule_id="PYH-IAC-005",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIGURATION,
                    title="Docker Compose Host Networking Mode",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Service '{res.name}' uses 'network_mode: host'.",
                    description="Host networking bypasses container isolation, exposing host network interfaces.",
                    remediation="Use custom user-defined bridge networks instead of host networking.",
                )
            )

        if res.is_publicly_exposed and any(p in res.exposed_ports for p in (22, 2375, 2376, 3306, 5432, 6379, 27017)):
            findings.append(
                Finding(
                    rule_id="PYH-IAC-006",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIGURATION,
                    title="Exposed Administrative/Database Port in Compose",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Service '{res.name}' exposes port(s) {res.exposed_ports} to 0.0.0.0.",
                    description="Exposing management or database ports to all network interfaces permits unauthorized access.",
                    remediation="Restrict host port binding to 127.0.0.1 or use isolated internal networks.",
                )
            )
        return findings

    def _evaluate_kubernetes(self, res: InfrastructureResource) -> List[Finding]:
        findings = []
        if res.type == InfrastructureResourceType.KUBERNETES_WORKLOAD:
            if res.is_privileged:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-007",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.CONFIGURATION,
                        title="Kubernetes Privileged Container",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Workload '{res.name}' has securityContext.privileged=true.",
                        description="Privileged pods can break out of container containment onto the host node.",
                        remediation="Remove privileged: true from securityContext.",
                    )
                )
            if res.runs_as_root:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-008",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category=Category.CONFIGURATION,
                        title="Kubernetes Pod Allows Root Execution",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Workload '{res.name}' missing runAsNonRoot=true in securityContext.",
                        description="Running pods as root increases host node compromise impact.",
                        remediation="Set securityContext.runAsNonRoot: true.",
                    )
                )
            if res.properties.get("hostNetwork") is True:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-009",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.CONFIGURATION,
                        title="Kubernetes Pod Host Network Shared",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Workload '{res.name}' sets hostNetwork=true.",
                        description="Pods using hostNetwork can sniff traffic and access host loopback services.",
                        remediation="Disable hostNetwork: true unless strictly required for CNI networking plugin pods.",
                    )
                )

        elif res.type == InfrastructureResourceType.KUBERNETES_RBAC:
            for pol in res.iam_policies:
                if pol.is_admin:
                    findings.append(
                        Finding(
                            rule_id="PYH-IAC-010",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=Category.AUTHENTICATION,
                            title="Kubernetes Wildcard RBAC Role",
                            file_path=res.file_path,
                            location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                            evidence=f"RBAC Role '{pol.name}' grants wildcard '*' permissions.",
                            description="Wildcard permissions grant cluster-admin capabilities, violating least privilege.",
                            remediation="Restrict RBAC verbs and resources to specific, explicit sets.",
                        )
                    )
        return findings

    def _evaluate_terraform(self, res: InfrastructureResource) -> List[Finding]:
        findings = []
        if res.is_publicly_exposed:
            if res.type == InfrastructureResourceType.CLOUD_STORAGE:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-011",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.CONFIGURATION,
                        title="Public Cloud Storage Bucket",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Storage resource '{res.name}' permits public read/write access.",
                        description="Public storage buckets expose proprietary data to unauthorized internet access.",
                        remediation="Enable public access blocks and set ACL to private.",
                    )
                )
            elif res.type == InfrastructureResourceType.CLOUD_DATABASE:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-012",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.CONFIGURATION,
                        title="Publicly Accessible Database Instance",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"Database '{res.name}' has publicly_accessible=true or open ingress.",
                        description="Exposing databases to public IP ranges allows direct brute-force attack vectors.",
                        remediation="Set publicly_accessible=false and isolate database within private subnets.",
                    )
                )

        if not res.has_encryption_enabled:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-013",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CRYPTOGRAPHY,
                    title="Cloud Resource Missing Encryption",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Resource '{res.name}' has server-side or in-transit encryption disabled.",
                    description="Unencrypted data at rest or in transit risks compliance violations and credential theft.",
                    remediation="Enable KMS/customer-managed encryption keys for storage and databases.",
                )
            )

        for pol in res.iam_policies:
            if pol.is_admin:
                findings.append(
                    Finding(
                        rule_id="PYH-IAC-014",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.AUTHENTICATION,
                        title="Wildcard Cloud IAM Policy",
                        file_path=res.file_path,
                        location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                        evidence=f"IAM policy '{pol.name}' grants wildcard '*' action or resource privileges.",
                        description="Wildcard IAM policies allow full cloud account takeover if credentials leak.",
                        remediation="Enforce least privilege by specifying exact actions and resources.",
                    )
                )
        return findings

    def _evaluate_cicd(self, res: InfrastructureResource) -> List[Finding]:
        findings = []
        unpinned = res.properties.get("unpinned_actions", [])
        if unpinned:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-015",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    title="Unpinned GitHub Action Workflow",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Workflow '{res.name}' uses unpinned action(s): {', '.join(unpinned[:3])}",
                    description="Actions pinned to mutable tags can be modified upstream to inject malicious steps.",
                    remediation="Pin third-party GitHub Actions to full 40-character commit SHAs.",
                )
            )

        triggers = res.properties.get("triggers", [])
        if "pull_request_target" in triggers:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-016",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIGURATION,
                    title="Dangerous pull_request_target Workflow Trigger",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Workflow '{res.name}' uses 'pull_request_target' event trigger.",
                    description="pull_request_target runs in the context of the base repo with access to repository secrets.",
                    remediation="Avoid checking out untrusted PR head code in pull_request_target workflows.",
                )
            )

        dangerous_runs = res.properties.get("dangerous_runs", [])
        if dangerous_runs:
            findings.append(
                Finding(
                    rule_id="PYH-IAC-017",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.INJECTION,
                    title="Possible Shell Command Injection in Workflow",
                    file_path=res.file_path,
                    location=Location(line_start=res.line, line_end=res.line, column_start=1, column_end=1),
                    evidence=f"Inline step run contains untrusted context variable: '{dangerous_runs[0]}'",
                    description="Interpolating untrusted PR/issue content directly into shell scripts allows command injection.",
                    remediation="Pass untrusted inputs into step environment variables instead of inline expressions.",
                )
            )
        return findings

