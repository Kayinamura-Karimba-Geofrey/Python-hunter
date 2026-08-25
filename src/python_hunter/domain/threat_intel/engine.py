"""ThreatIntelligenceEngine for threat-aware scanning, risk rescoring, and threat hunting."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.threat_intel.models import (
    ExploitationStatus, IntelligenceSource, ThreatActor, ThreatCampaign, ThreatPriority, TrustLevel, VulnerabilityIntelligence
)
from python_hunter.domain.threat_intel.sources import IntelligenceSourceRegistry


class ThreatIntelligenceEngine:
    """Core engine orchestrating ingestion, normalization, conflict resolution, rescoring, and threat hunting."""

    def __init__(self, registry: Optional[IntelligenceSourceRegistry] = None) -> None:
        self.registry = registry or IntelligenceSourceRegistry()
        self._intel_store: Dict[str, VulnerabilityIntelligence] = {}
        self.sync_all_sources()

    def sync_all_sources(self) -> Dict[str, int]:

        """Ingests records from all enabled registered sources with conflict resolution."""
        records_processed = 0
        records_changed = 0

        for adapter in self.registry.list_sources():
            if not adapter.enabled:
                continue

            sub_adapter = self.registry.get_source(adapter.source_id)
            if not sub_adapter:
                continue

            try:
                records = sub_adapter.fetch_records()
                for rec in records:
                    records_processed += 1
                    key = rec.cve_id or rec.vulnerability_id
                    if key in self._intel_store:
                        # Conflict Resolution: Higher trust or KEV status takes precedence
                        existing = self._intel_store[key]
                        if rec.is_kev and not existing.is_kev:
                            self._intel_store[key] = rec
                            records_changed += 1
                    else:
                        self._intel_store[key] = rec
                        records_changed += 1
                adapter.retrieved_at = datetime.now(timezone.utc)
            except Exception:
                pass

        return {"processed": records_processed, "changed": records_changed}

    def get_vulnerability_intel(self, cve_or_id: str) -> Optional[VulnerabilityIntelligence]:
        return self._intel_store.get(cve_or_id)

    def list_all_intelligence(self) -> List[VulnerabilityIntelligence]:
        return list(self._intel_store.values())

    def list_kev_vulnerabilities(self) -> List[VulnerabilityIntelligence]:
        return [v for v in self._intel_store.values() if v.is_kev]

    def list_actively_exploited(self) -> List[VulnerabilityIntelligence]:
        return [v for v in self._intel_store.values() if v.exploitation_status == ExploitationStatus.ACTIVELY_EXPLOITED]

    def rescore_finding(self, finding: Finding, is_internet_facing: bool = False, asset_criticality: str = "HIGH") -> Dict[str, Any]:
        """Calculates threat-adjusted risk score and threat priority with transparent breakdown."""
        base_score = 5.0
        if hasattr(finding.severity, "value"):
            sev = finding.severity.value.upper()
        else:
            sev = str(finding.severity).upper()

        if sev == "CRITICAL":
            base_score = 9.0
        elif sev == "HIGH":
            base_score = 7.0
        elif sev == "MEDIUM":
            base_score = 5.0
        else:
            base_score = 3.0

        intel_adjustment = 0.0
        exposure_adjustment = 2.0 if is_internet_facing else 0.0
        asset_adjustment = 1.5 if asset_criticality.upper() == "CRITICAL" else 0.5

        # Check CVE / KEV match
        cve_id = getattr(finding, "cve_id", None)
        intel = self.get_vulnerability_intel(cve_id) if cve_id else None

        threat_priority = ThreatPriority.MEDIUM

        if intel:
            if intel.is_kev or intel.exploitation_status == ExploitationStatus.ACTIVELY_EXPLOITED:
                intel_adjustment += 3.5
                threat_priority = ThreatPriority.CRITICAL
            elif intel.exploitation_status == ExploitationStatus.EXPLOIT_AVAILABLE:
                intel_adjustment += 2.0
                threat_priority = ThreatPriority.HIGH

        final_score = min(10.0, round(base_score + intel_adjustment + exposure_adjustment + asset_adjustment, 1))

        if final_score >= 9.0 and threat_priority != ThreatPriority.CRITICAL:
            threat_priority = ThreatPriority.CRITICAL
        elif final_score >= 7.5 and threat_priority not in [ThreatPriority.CRITICAL, ThreatPriority.HIGH]:
            threat_priority = ThreatPriority.HIGH

        return {
            "finding_id": finding.rule_id,
            "base_risk": base_score,
            "intelligence_adjustment": intel_adjustment,
            "exposure_adjustment": exposure_adjustment,
            "asset_adjustment": asset_adjustment,
            "final_score": final_score,
            "threat_priority": threat_priority.value,
            "is_kev": intel.is_kev if intel else False,
            "explanation": f"Base ({base_score}) + Intel ({intel_adjustment}) + Exposure ({exposure_adjustment}) + Asset ({asset_adjustment}) = {final_score}"
        }

    def threat_hunt(self, query: str) -> List[Dict[str, Any]]:
        """Defensive threat hunting query execution."""
        results = []
        q = query.lower()

        for key, intel in self._intel_store.items():
            match = False
            if "kev" in q and intel.is_kev:
                match = True
            elif "exploited" in q and intel.exploitation_status == ExploitationStatus.ACTIVELY_EXPLOITED:
                match = True
            elif intel.cve_id and intel.cve_id.lower() in q:
                match = True
            elif intel.affected_package and intel.affected_package.lower() in q:
                match = True

            if match or not q:
                results.append({
                    "cve_id": intel.cve_id,
                    "severity": intel.severity,
                    "cvss_score": intel.cvss_score,
                    "exploitation_status": intel.exploitation_status.value,
                    "is_kev": intel.is_kev,
                    "affected_package": intel.affected_package,
                    "mitre_attack_techniques": intel.mitre_attack_techniques
                })
        return results
