"""Read-side queries over persisted scan records.

Every dashboard and API view (findings, repositories, history, regressions, dependencies,
policies, compliance) is derived from scans that actually ran and were saved to the
ScanResultStore. With no recorded scans, the views are empty rather than populated
with sample data.
"""

import os
from itertools import pairwise
from typing import Any

from python_hunter.application.orchestrator.scan_context import ScanResult
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.policy.policy_evaluator import PolicyEngine
from python_hunter.domain.policy.policy_models import PolicyAction
from python_hunter.infrastructure.storage.scan_store import ScanResultStore

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
_REGRESSION_SEVERITIES = ("CRITICAL", "HIGH")

_EXTENSION_LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".cpp": "C++",
}

# OWASP Top 10 (2021) controls and the finding categories that count as evidence against them.
OWASP_CONTROLS: list[dict[str, Any]] = [
    {
        "control_id": "A01:2021-Broken Access Control",
        "title": "Enforce least privilege and endpoint authorization",
        "categories": {"AUTHORIZATION", "PATH_TRAVERSAL", "API_SECURITY"},
        "remediation": "Add authorization checks to every exposed endpoint and validate file paths.",
    },
    {
        "control_id": "A02:2021-Cryptographic Failures",
        "title": "Protect secrets and use strong cryptography",
        "categories": {"CRYPTOGRAPHY", "SECRET", "SECRET_LEAK", "GIT_HISTORY"},
        "remediation": "Move secrets to a secret manager, rotate leaked credentials, and use modern algorithms.",
    },
    {
        "control_id": "A03:2021-Injection",
        "title": "Sanitize and parameterize all data queries",
        "categories": {"INJECTION", "CODE_INJECTION", "TAINT", "TAINT_ANALYSIS", "DYNAMIC_EXECUTION"},
        "remediation": "Use parameterized queries and avoid passing user input to interpreters.",
    },
    {
        "control_id": "A05:2021-Security Misconfiguration",
        "title": "Harden configuration and infrastructure defaults",
        "categories": {"CONFIGURATION", "FRAMEWORK"},
        "remediation": "Disable debug modes and apply secure framework and infrastructure defaults.",
    },
    {
        "control_id": "A06:2021-Vulnerable and Outdated Components",
        "title": "Keep third-party components patched",
        "categories": {"DEPENDENCY", "VULNERABLE_DEPENDENCY"},
        "remediation": "Upgrade vulnerable dependencies to their fixed versions.",
    },
    {
        "control_id": "A07:2021-Identification and Authentication Failures",
        "title": "Require strong authentication",
        "categories": {"AUTHENTICATION"},
        "remediation": "Enforce authentication on sensitive routes and use vetted session handling.",
    },
    {
        "control_id": "A08:2021-Software and Data Integrity Failures",
        "title": "Verify the integrity of code and data",
        "categories": {"SUPPLY_CHAIN", "UNSAFE_DESERIALIZATION", "MALWARE_RISK"},
        "remediation": "Pin and verify dependencies and never deserialize untrusted data.",
    },
]


def _language_for(file_path: str) -> str:
    return _EXTENSION_LANGUAGES.get(os.path.splitext(file_path)[1].lower(), "Unknown")


def finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialize a domain Finding into the shape the API and dashboard consume."""
    meta = f.metadata or {}
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "rule_id": f.rule_id,
        "category": f.category.value,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "risk_score": float(f.risk_score),
        "exploitability_score": float(meta.get("exploitability_score", 0.0)),
        "language": meta.get("language") or _language_for(f.file_path),
        "framework": meta.get("framework"),
        "file_path": f.file_path,
        "line_number": f.location.line_start if f.location else 0,
        "function_name": meta.get("function_name"),
        "code_snippet": f.evidence,
        "description": f.description,
        "remediation_guidance": f.remediation,
        "why_it_matters": meta.get("why_it_matters", ""),
        "status": f.status.value,
        "service_name": meta.get("service_name"),
        "endpoint": meta.get("endpoint"),
        "metadata": {k: v for k, v in meta.items() if isinstance(v, (str, int, float, bool, type(None)))},
    }


def _attack_path_to_dict(path: Any, graph: Any) -> dict[str, Any]:
    nodes_by_id = graph.nodes if graph is not None else {}
    nodes = []
    for node_id in path.path_node_ids:
        node = nodes_by_id.get(node_id)
        nodes.append(
            {
                "id": node_id,
                "label": node.name if node else node_id,
                "type": node.type.value.lower() if node else "asset",
                "risk_score": float(node.risk_score) if node else 0.0,
            }
        )
    edges = []
    for src, dst in pairwise(path.path_node_ids):
        relationship = "dataflow"
        if graph is not None:
            edge = next((e for e in graph.get_neighbors(src) if e.target_id == dst), None)
            if edge is not None:
                relationship = edge.relationship.value.lower()
        edges.append({"source": src, "target": dst, "label": relationship.replace("_", " "), "type": relationship})

    entry = nodes[0]["label"] if nodes else path.entry_point_id
    target = nodes[-1]["label"] if nodes else path.target_asset_id
    return {
        "id": path.id,
        "title": path.title,
        "entry_point": entry,
        "target_asset": target,
        "affected_services": [n["label"] for n in nodes if n["type"] == "service"],
        "risk_score": float(path.risk_score),
        "exploitability_score": float(path.risk_score) / 10.0,
        "confidence": path.confidence.value,
        "remediation": path.remediation_guidance,
        "nodes": nodes,
        "edges": edges,
    }


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def security_score(counts: dict[str, int]) -> int:
    """100 minus a per-severity penalty, floored at 0."""
    penalty = sum(_SEVERITY_PENALTY.get(sev, 0) * n for sev, n in counts.items())
    return max(0, 100 - penalty)


def risk_level(counts: dict[str, int]) -> str:
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if counts.get(sev):
            return sev
    return "LOW"


def build_scan_record(
    scan_id: str,
    target: str,
    profile: str,
    result: ScanResult,
    gate: Any,
    created_at: str,
) -> dict[str, Any]:
    """Convert an orchestrator ScanResult into a persisted, JSON-serializable record."""
    findings = [finding_to_dict(f) for f in result.findings]
    counts = severity_counts(findings)
    ci = result.context.ci_metadata if result.context else {}
    return {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "status": "COMPLETED",
        "created_at": created_at,
        "completed_at": result.context.end_time if result.context else created_at,
        "commit": (ci or {}).get("sha", ""),
        "findings": findings,
        "findings_count": len(findings),
        "counts_by_severity": counts,
        "security_score": security_score(counts),
        "risk_level": risk_level(counts),
        "risk_score": float(result.project_risk.overall_score) if result.project_risk else 0.0,
        "gate_status": gate.status.value,
        "violations": list(gate.violations),
        "exit_code": gate.exit_code,
        "attack_paths": [_attack_path_to_dict(p, result.graph) for p in result.attack_paths],
    }


class ScanQueryService:
    """Answers dashboard and API queries from persisted scan records."""

    def __init__(self, store: ScanResultStore, policy_engine: PolicyEngine | None = None) -> None:
        self.store = store
        self.policy_engine = policy_engine or PolicyEngine()

    def _completed(self) -> list[dict[str, Any]]:
        return self.store.list_scans(status="COMPLETED")

    def _latest_findings(self) -> list[dict[str, Any]]:
        latest = self.store.latest_scan()
        return list(latest["findings"]) if latest else []

    def list_findings(
        self, severity: str | None = None, status: str | None = None, search: str | None = None
    ) -> list[dict[str, Any]]:
        results = self._latest_findings()
        if severity:
            results = [f for f in results if f["severity"].upper() == severity.upper()]
        if status:
            results = [f for f in results if f["status"].upper() == status.upper()]
        if search:
            s = search.lower()
            results = [
                f
                for f in results
                if s in f["title"].lower() or s in f["rule_id"].lower() or s in f["file_path"].lower()
            ]
        return results

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return next((f for f in self._latest_findings() if f["id"] == finding_id), None)

    def get_dashboard_summary(self) -> dict[str, Any]:
        scans = self._completed()
        latest = scans[-1] if scans else None
        previous = scans[-2] if len(scans) > 1 else None
        counts = latest["counts_by_severity"] if latest else severity_counts([])
        score = latest["security_score"] if latest else 100
        prev_score = previous["security_score"] if previous else score
        gate = latest["gate_status"] if latest else "PASS"
        return {
            "security_score": score,
            "previous_score": prev_score,
            "score_delta": score - prev_score,
            "risk_level": latest["risk_level"] if latest else "LOW",
            "gate_status": gate,
            "counts_by_severity": counts,
            "new_regressions_count": len(self.list_regressions()),
            "total_findings": latest["findings_count"] if latest else 0,
            "total_repositories": len({s["target"] for s in scans}),
            "total_scans": len(scans),
            "failed_policies_count": sum(1 for p in self.list_policies() if p["status"] == "FAIL"),
            "warnings_count": sum(1 for p in self.list_policies() if p["status"] == "WARN"),
            "exceptions_count": 0,
        }

    def list_repositories(self) -> list[dict[str, Any]]:
        latest_by_target: dict[str, dict[str, Any]] = {}
        for scan in self._completed():
            latest_by_target[scan["target"]] = scan
        repos = []
        for idx, (target, scan) in enumerate(sorted(latest_by_target.items()), 1):
            is_remote = target.startswith(("http://", "https://", "git@"))
            name = target.rstrip("/").removesuffix(".git").split("/")[-1] if is_remote else os.path.basename(
                os.path.abspath(target)
            )
            repos.append(
                {
                    "id": f"repo-{idx}",
                    "name": name or target,
                    "provider": "github" if "github.com" in target else ("git" if is_remote else "local"),
                    "url_or_path": target,
                    "default_branch": "main",
                    "last_scan_at": scan["completed_at"],
                    "security_score": scan["security_score"],
                    "risk_level": scan["risk_level"],
                    "open_findings_count": scan["findings_count"],
                    "status": "HEALTHY" if scan["gate_status"] == "PASS" else "AT_RISK",
                }
            )
        return repos

    def list_history(self) -> list[dict[str, Any]]:
        history = []
        previous: set[str] = set()
        for scan in self._completed():
            current = {f["fingerprint"] for f in scan["findings"]}
            counts = scan["counts_by_severity"]
            new = current - previous
            history.append(
                {
                    "timestamp": scan["completed_at"],
                    "commit": scan.get("commit", "")[:7],
                    "score": scan["security_score"],
                    "critical_count": counts.get("CRITICAL", 0),
                    "high_count": counts.get("HIGH", 0),
                    "medium_count": counts.get("MEDIUM", 0),
                    "low_count": counts.get("LOW", 0),
                    "new_findings": len(new) if previous else 0,
                    "fixed_findings": len(previous - current),
                    "regressions": sum(
                        1 for f in scan["findings"] if f["fingerprint"] in new and f["severity"] in _REGRESSION_SEVERITIES
                    )
                    if previous
                    else 0,
                }
            )
            previous = current
        return history

    def list_regressions(self) -> list[dict[str, Any]]:
        """CRITICAL/HIGH findings in the latest scan of a target that its previous scan did not have."""
        by_target: dict[str, list[dict[str, Any]]] = {}
        for scan in self._completed():
            by_target.setdefault(scan["target"], []).append(scan)
        regressions = []
        for scans in by_target.values():
            if len(scans) < 2:
                continue
            prev, latest = scans[-2], scans[-1]
            prev_fps = {f["fingerprint"] for f in prev["findings"]}
            for f in latest["findings"]:
                if f["fingerprint"] in prev_fps or f["severity"] not in _REGRESSION_SEVERITIES:
                    continue
                regressions.append(
                    {
                        "id": f"reg-{f['fingerprint'][:12]}",
                        "regression_type": f"NEW_{f['severity']}_FINDING",
                        "severity": f["severity"],
                        "commit": latest.get("commit", "")[:7],
                        "status": "OPEN",
                        "risk_impact": "SECURITY_SCORE_DECREASED",
                        "previous_state": prev["gate_status"],
                        "current_state": latest["gate_status"],
                        "introducing_commit": latest.get("commit", "")[:7],
                        "fixing_commit": None,
                        "affected_files": [f["file_path"]],
                        "affected_endpoint": f.get("endpoint"),
                    }
                )
        return regressions

    def list_attack_paths(self) -> list[dict[str, Any]]:
        latest = self.store.latest_scan()
        return list(latest.get("attack_paths", [])) if latest else []

    def list_dependencies(self) -> list[dict[str, Any]]:
        """Vulnerable dependencies reported by the SCA rules in the latest scan."""
        deps: dict[str, dict[str, Any]] = {}
        for f in self._latest_findings():
            meta = f.get("metadata") or {}
            name = meta.get("package_name")
            if not name:
                continue
            key = f"{meta.get('ecosystem', '')}:{name}:{meta.get('version', '')}"
            if key in deps:
                continue
            deps[key] = {
                "id": f"dep-{len(deps) + 1}",
                "package_name": name,
                "current_version": meta.get("version") or "unknown",
                "ecosystem": meta.get("ecosystem", ""),
                "is_direct": bool(meta.get("is_direct", True)),
                "is_production": bool(meta.get("is_production", True)),
                "vulnerability_status": "VULNERABLE",
                "vulnerable_versions": None,
                "advisory_id": meta.get("advisory_id"),
                "severity": f["severity"],
                "fixed_in_version": meta.get("fixed_in_version"),
                "risk_score": f["risk_score"],
            }
        return list(deps.values())

    def list_policies(self) -> list[dict[str, Any]]:
        latest = self.store.latest_scan()
        violations = latest["violations"] if latest else []
        policies = []
        for pol in self.policy_engine.STRICT_PROFILE:
            hits = [v for v in violations if v.startswith(f"{pol.name}:")]
            if not hits:
                status = "PASS"
            else:
                status = "FAIL" if pol.action == PolicyAction.FAIL else "WARN"
            cond = pol.condition
            conditions = []
            if cond.severity:
                conditions.append(f"{cond.severity.value.lower()}_findings < {cond.min_count}")
            if cond.min_risk_score:
                conditions.append(f"risk_score < {cond.min_risk_score}")
            if cond.tags:
                conditions.append(f"no findings tagged {', '.join(cond.tags)}")
            affected = 0
            if cond.severity and latest:
                affected = latest["counts_by_severity"].get(cond.severity.value, 0)
            policies.append(
                {
                    "id": pol.policy_id,
                    "name": pol.name,
                    "description": pol.description,
                    "status": status,
                    "conditions": conditions,
                    "affected_findings_count": affected,
                    "exceptions_count": 0,
                }
            )
        return policies

    def list_compliance(self) -> list[dict[str, Any]]:
        latest = self.store.latest_scan()
        findings = latest["findings"] if latest else []
        controls = []
        for idx, control in enumerate(OWASP_CONTROLS, 1):
            affected = [f for f in findings if f.get("category") in control["categories"]]
            if not latest:
                status = "NOT_ASSESSED"
            else:
                status = "FAIL" if affected else "PASS"
            controls.append(
                {
                    "id": f"comp-{idx}",
                    "framework": "OWASP Top 10 2021",
                    "control_id": control["control_id"],
                    "title": control["title"],
                    "status": status,
                    "evidence_count": len(affected),
                    "affected_findings_count": len(affected),
                    "remediation_summary": control["remediation"] if affected else "No findings mapped to this control.",
                }
            )
        return controls

    def list_reports(self) -> list[dict[str, Any]]:
        return [
            {
                "id": f"rep-{scan['scan_id']}",
                "report_type": "JSON",
                "scan_id": scan["scan_id"],
                "created_at": scan["completed_at"],
                "status": "READY",
                "download_url": f"/api/v1/scans/{scan['scan_id']}",
            }
            for scan in reversed(self._completed())
        ]
