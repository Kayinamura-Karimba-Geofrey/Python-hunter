"""Finding Correlation Engine & Root Cause Analyzer."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from python_hunter.domain.common.enums import Confidence, Severity, FindingRelationType
from python_hunter.domain.graph.models import SecurityGraph, NodeType, EdgeType, SecurityNode, SecurityEdge


class CauseCategory(str, Enum):
    ROOT_CAUSE = "ROOT_CAUSE"
    CONTRIBUTING_CONDITION = "CONTRIBUTING_CONDITION"
    DOWNSTREAM_CONSEQUENCE = "DOWNSTREAM_CONSEQUENCE"


@dataclass
class FindingCluster:
    """Logical cluster combining duplicate or related security findings across scanners."""

    id: str
    title: str
    primary_finding_id: str
    member_finding_ids: List[str] = field(default_factory=list)
    root_cause_finding_id: Optional[str] = None
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.HIGH
    categories: Set[str] = field(default_factory=set)
    shared_resource: Optional[str] = None
    shared_vulnerability: Optional[str] = None
    description: str = ""
    remediation_summary: str = ""


class CorrelationEngine:
    """Correlates individual findings across SAST, SCA, Secrets, Containers, K8s, Cloud, and CI/CD."""

    def correlate_findings(
        self,
        findings: List[Dict[str, Any]],
        graph: SecurityGraph,
    ) -> List[FindingCluster]:
        """Groups findings into logical clusters, identifies duplicates, and marks root causes."""
        if not findings:
            return []

        clusters: List[FindingCluster] = []
        visited: Set[str] = set()

        # 1. Group duplicate findings (same file + line or same CVE + location)
        dup_groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            fid = f.get("id") or f.get("rule_id", "unknown")
            file_p = f.get("file_path", "")
            line = f.get("line_number") or f.get("line", 0)
            rule = f.get("rule_id", "")
            key = f"{file_p}:{line}:{rule}" if file_p else f"{rule}:{f.get('title')}"
            dup_groups.setdefault(key, []).append(f)

        cluster_idx = 1
        for key, group in dup_groups.items():
            primary = group[0]
            member_ids = [g.get("id") or f"find-{i}" for i, g in enumerate(group)]
            
            # Determine root cause vs downstream consequence
            root_cause_id = member_ids[0]
            
            severities = [g.get("severity", "MEDIUM") for g in group]
            top_sev = self._highest_severity(severities)

            cluster = FindingCluster(
                id=f"cluster-{cluster_idx}",
                title=primary.get("title") or primary.get("rule_name") or "Correlated Security Issue",
                primary_finding_id=root_cause_id,
                member_finding_ids=member_ids,
                root_cause_finding_id=root_cause_id,
                severity=top_sev,
                confidence=Confidence.HIGH,
                categories={primary.get("category", "CODE_SECURITY")},
                shared_resource=primary.get("file_path"),
                shared_vulnerability=primary.get("rule_id"),
                description=primary.get("description", ""),
                remediation_summary=primary.get("remediation", ""),
            )
            clusters.append(cluster)
            cluster_idx += 1

        return clusters

    def _highest_severity(self, severities: List[str]) -> Severity:
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_val = -1
        top_sev = Severity.MEDIUM
        for s in severities:
            val = sev_map.get(str(s).upper(), 1)
            if val > max_val:
                max_val = val
                top_sev = Severity(str(s).upper()) if str(s).upper() in Severity.__members__ else Severity.MEDIUM
        return top_sev


class RootCauseAnalyzer:
    """Determines whether a finding is a root cause, contributing condition, or downstream consequence."""

    @staticmethod
    def analyze_finding_role(finding: Dict[str, Any], graph: SecurityGraph) -> CauseCategory:
        rule_id = str(finding.get("rule_id", ""))
        file_path = str(finding.get("file_path", ""))

        # IAM, unpinned action, unauthenticated endpoint, exposed secret -> Root Causes
        if any(rc in rule_id for rc in ("IAM", "SECRET", "AUTH", "015", "016", "SQLI", "RCE")):
            return CauseCategory.ROOT_CAUSE
        # Container privilege, missing encryption, outdated dep -> Contributing Conditions
        if any(cc in rule_id for cc in ("006", "007", "CVE", "DEP", "PRIVILEGED")):
            return CauseCategory.CONTRIBUTING_CONDITION
        return CauseCategory.DOWNSTREAM_CONSEQUENCE
