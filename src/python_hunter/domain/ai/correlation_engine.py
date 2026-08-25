"""Finding Correlation Engine & Duplicate Detection across scanners and commits."""

from typing import Any, Dict, List, Set, Tuple
from python_hunter.domain.findings.finding import Finding


class FindingCorrelationEngine:
    """Correlates related security findings and detects duplicates across analyzers and commits."""

    def correlate(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Groups related findings into unified security risk clusters."""
        if not findings:
            return []

        clusters: Dict[str, List[Finding]] = {}
        for f in findings:
            # Group by file path or rule category
            loc_key = f.location.file_path if f.location else f.rule_id
            clusters.setdefault(loc_key, []).append(f)

        correlated_groups = []
        for cluster_id, group in clusters.items():
            rule_ids = list({f.rule_id for f in group})
            severities = [f.severity.value for f in group if hasattr(f, 'severity')]
            correlated_groups.append({
                "cluster_id": cluster_id,
                "finding_count": len(group),
                "rule_ids": rule_ids,
                "findings": group,
                "correlation_summary": f"Correlated {len(group)} related finding(s) under {cluster_id}"
            })

        return correlated_groups

    def detect_duplicates(self, findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Separates unique findings from duplicate/near-duplicate findings."""
        seen_keys: Set[str] = set()
        unique: List[Finding] = []
        duplicates: List[Finding] = []

        for f in findings:
            loc_str = f"{f.location.file_path}:{f.location.start_line}" if f.location else "no_loc"
            dedup_key = f"{f.rule_id}:{loc_str}:{f.title}"
            if dedup_key in seen_keys:
                duplicates.append(f)
            else:
                seen_keys.add(dedup_key)
                unique.append(f)

        return unique, duplicates
