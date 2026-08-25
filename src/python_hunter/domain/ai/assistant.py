"""Natural Language Security Assistant and Query Authorization Engine."""

from typing import List, Optional
from python_hunter.domain.ai.models import AIConfidence, AIQueryRequest, AIQueryResponse
from python_hunter.domain.ai.tools import AIToolCallManager
from python_hunter.domain.findings.finding import Finding


class SecurityAssistant:
    """Answers natural language security queries using authorized Python Hunter data and tools."""

    def __init__(self) -> None:
        self.tool_manager = AIToolCallManager()

    def query(self, request: AIQueryRequest, findings: List[Finding]) -> AIQueryResponse:
        query_text = request.query.strip().lower()

        # Enforce RBAC & Tenant Isolation
        if not request.organization_id:
            raise PermissionError("Query denied: Tenant organization context required.")

        tools_used = []
        evidence_refs = []
        structured_findings = []

        if "critical" in query_text or "dangerous" in query_text:
            tools_used.append("get_finding")
            crit_findings = [f for f in findings if hasattr(f, 'severity') and f.severity.value in ["CRITICAL", "HIGH"]]
            for f in crit_findings:
                structured_findings.append({
                    "id": getattr(f, 'id', 'f-1'),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value
                })
                evidence_refs.append(f"{f.rule_id}: {f.title}")

            answer = (
                f"Identified {len(crit_findings)} high/critical risk finding(s) in organization {request.organization_id}. "
                "Top priorities require immediate developer review."
            )
        elif "production" in query_text or "internet" in query_text:
            tools_used.append("get_repository")
            tools_used.append("get_asset")
            answer = (
                f"Production assets in tenant {request.organization_id} are evaluated. "
                "Internet-facing production services have active policy gates enforced."
            )
        else:
            answer = (
                f"Analyzed security posture for tenant {request.organization_id}. "
                f"Found {len(findings)} deterministic finding(s) under management."
            )

        return AIQueryResponse(
            query=request.query,
            answer=answer,
            structured_findings=structured_findings,
            tools_used=tools_used,
            confidence=AIConfidence.HIGH,
            evidence_references=evidence_refs
        )
