"""Finding Correlator and Attack Path Engine."""

import logging
from typing import Any

from python_hunter.domain.common.enums import (
    AttackPathType,
    Category,
    Confidence,
    ExposureType,
    FindingRelationType,
    ReachabilityType,
    Severity,
)
from python_hunter.domain.correlation.models import (
    AttackPath,
    AttackPathNode,
    FindingRelationship,
)
from python_hunter.domain.findings.finding import Finding

logger = logging.getLogger(__name__)


class FindingCorrelator:
    """Correlates security findings across AST, secrets, dependencies, taint, git, and call graphs."""

    def __init__(self) -> None:
        self.relationships: list[FindingRelationship] = []

    def correlate(
        self,
        raw_findings: list[Finding],
        callgraph_data: dict[str, Any] | None = None,
        taint_flows: list[Any] | None = None,
        git_history: list[Any] | None = None,
    ) -> tuple[list[Finding], list[AttackPath]]:
        """Deduplicate raw findings, enrich with cross-analyzer context, and construct attack paths."""
        # 1. Deduplicate by fingerprint
        deduped = self._deduplicate_findings(raw_findings)

        # 2. Enrich findings with call graph reachability & taint context
        self._enrich_findings(deduped, callgraph_data, taint_flows, git_history)

        # 3. Construct attack paths from correlated evidence
        attack_paths = self._build_attack_paths(deduped, callgraph_data, taint_flows)

        return deduped, attack_paths

    def _deduplicate_findings(self, raw_findings: list[Finding]) -> list[Finding]:
        """Group findings by fingerprint or matching source/sink location."""
        grouped: dict[str, list[Finding]] = {}
        for f in raw_findings:
            key = f.fingerprint
            grouped.setdefault(key, []).append(f)

        deduped: list[Finding] = []
        for key, group in grouped.items():
            if len(group) == 1:
                deduped.append(group[0])
            else:
                # Pick primary finding (prefer TAINT or INJECTION or higher severity)
                primary = max(
                    group,
                    key=lambda x: (
                        10 if x.category in (Category.TAINT, Category.INJECTION, Category.CODE_INJECTION) else 0,
                        x.severity.weight,
                        x.confidence.multiplier,
                    ),
                )
                for f in group:
                    if f.id != primary.id:
                        primary.secondary_evidence.append(
                            f"Correlated Analyzer [{f.rule_id}]: {f.evidence or f.description}"
                        )
                        primary.related_findings.append(f.id)
                        self.relationships.append(
                            FindingRelationship(
                                source_finding_id=primary.id,
                                target_finding_id=f.id,
                                relation_type=FindingRelationType.DUPLICATE,
                                description=f"Merged duplicate finding from rule {f.rule_id}",
                            )
                        )
                deduped.append(primary)

        return deduped

    def _enrich_findings(
        self,
        findings: list[Finding],
        callgraph_data: dict[str, Any] | None,
        taint_flows: list[Any] | None,
        git_history: list[Any] | None,
    ) -> None:
        """Apply cross-analyzer contextual enrichment (exposure, reachability, data sensitivity)."""
        entry_points = set()
        if callgraph_data and "entry_points" in callgraph_data:
            for ep in callgraph_data["entry_points"]:
                entry_points.add(ep.file_path)

        for f in findings:
            # Detect exposure from entry points if UNKNOWN
            if f.exposure == ExposureType.UNKNOWN:
                if f.file_path in entry_points or "request" in f.evidence.lower() or "route" in f.evidence.lower() or "request" in f.source.lower():
                    f.exposure = ExposureType.INTERNET_FACING
                elif "cli" in f.file_path.lower() or "main" in f.file_path.lower():
                    f.exposure = ExposureType.LOCAL
                else:
                    f.exposure = ExposureType.INTERNAL

            # Enrich taint findings
            if f.category in (Category.TAINT, Category.INJECTION, Category.CODE_INJECTION):
                f.reachability = ReachabilityType.REACHABLE
                if f.exposure == ExposureType.INTERNET_FACING:
                    f.tags.append("internet-facing-taint")

            # Enrich secrets with Git history correlation
            if f.category in (Category.SECRET, Category.SECRET_LEAK) and git_history:
                f.tags.append("git-history-verified")
                f.secondary_evidence.append("Correlated secret committed in historic Git commits.")

    def _build_attack_paths(
        self,
        findings: list[Finding],
        callgraph_data: dict[str, Any] | None,
        taint_flows: list[Any] | None,
    ) -> list[AttackPath]:
        """Construct multi-step AttackPath chains from correlated taint and call graph paths."""
        attack_paths: list[AttackPath] = []

        for f in findings:
            # Construct AttackPath for high-risk injection/taint findings with entry points
            if (
                f.category in (Category.TAINT, Category.INJECTION, Category.CODE_INJECTION, Category.PATH_TRAVERSAL)
                and f.exposure in (ExposureType.INTERNET_FACING, ExposureType.AUTHENTICATED)
            ):
                attack_type = AttackPathType.COMMAND_INJECTION
                if "sql" in f.title.lower() or "sql" in f.rule_id.lower():
                    attack_type = AttackPathType.SQL_INJECTION
                elif "path" in f.title.lower() or "traversal" in f.rule_id.lower():
                    attack_type = AttackPathType.PATH_TRAVERSAL
                elif "eval" in f.title.lower() or "code" in f.title.lower():
                    attack_type = AttackPathType.REMOTE_CODE_EXECUTION

                entry_label = f.source or "HTTP Request Parameter"
                sink_label = f.sink or f.evidence or "Security Sink"
                line_no = f.location.line_start if f.location else 0

                n1 = AttackPathNode(
                    step_number=1,
                    label=f"Untrusted Input Entry: {entry_label}",
                    file_path=f.file_path,
                    line_number=line_no,
                    node_type="ENTRY",
                    code_snippet=f.source,
                )
                n2 = AttackPathNode(
                    step_number=2,
                    label=f"Exploitable Sink Execution: {sink_label}",
                    file_path=f.file_path,
                    line_number=line_no,
                    node_type="SINK",
                    code_snippet=f.evidence,
                )

                path = AttackPath(
                    attack_type=attack_type,
                    title=f"Exploitable {attack_type.value} via {f.file_path}:{line_no}",
                    entry_point=entry_label,
                    target_sink=sink_label,
                    nodes=[n1, n2],
                    associated_finding_ids=[f.id],
                    risk_score=min(100.0, f.severity.weight * 10 + 20),
                    confidence=f.confidence,
                    explanation=f"Public HTTP entry point input reaches dangerous sink ({sink_label}) without sanitization.",
                )

                f.attack_path_id = path.id
                attack_paths.append(path)

        return attack_paths
