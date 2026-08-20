"""Knowledge Graph and Attack Path Engine Integration for Secrets Exposure."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.secrets.models import ExposureType, SecretEnvironment, SecretType


@dataclass
class SecretAttackPathNode:
    node_id: str
    node_type: str  # REPOSITORY, SECRET, SERVICE, ASSET, ENVIRONMENT
    name: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretAttackPath:
    path_id: str
    title: str
    severity: str
    steps: List[str] = field(default_factory=list)
    nodes: List[SecretAttackPathNode] = field(default_factory=list)
    remediation_summary: str = ""


class AttackPathSecretMapper:
    """Maps secret exposure findings into graph nodes and constructs end-to-end exploitability attack paths."""

    @classmethod
    def generate_attack_paths(cls, findings: List[Finding]) -> List[SecretAttackPath]:
        paths: List[SecretAttackPath] = []

        for idx, finding in enumerate(findings):
            if finding.category.value != "SECRET_LEAK":
                continue

            sec_type = finding.rule_id
            title = f"Attack Path: {finding.title}"

            n_repo = SecretAttackPathNode("node_repo", "REPOSITORY", "Target Workspace Repository")
            n_sec = SecretAttackPathNode("node_secret", "SECRET", finding.title, {"fingerprint": finding.fingerprint})
            n_service = SecretAttackPathNode("node_service", "SERVICE", "Application Backend Service")
            n_asset = SecretAttackPathNode("node_asset", "ASSET", "Cloud Infrastructure / Database Resource")

            steps = [
                "1. Attacker discovers public/private repository or Git history commit.",
                f"2. Attacker extracts exposed credential ({sec_type}) at {finding.file_path}:{finding.location.line_start}.",
                "3. Attacker authenticates against internal services or cloud provider APIs.",
                "4. Attacker escalates privileges or accesses sensitive data assets.",
            ]

            paths.append(
                SecretAttackPath(
                    path_id=f"ap_sec_{idx+1}",
                    title=title,
                    severity=finding.severity.value,
                    steps=steps,
                    nodes=[n_repo, n_sec, n_service, n_asset],
                    remediation_summary=finding.remediation,
                )
            )

        return paths
