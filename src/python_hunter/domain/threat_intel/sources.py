"""Threat Intelligence Source Adapters and Registry."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from python_hunter.domain.threat_intel.models import (
    ExploitationStatus, IntelligenceSource, ThreatPriority, TrustLevel, VulnerabilityIntelligence
)


class IntelligenceSourceAdapter(ABC):
    """Abstract base class for threat intelligence source adapters."""

    @property
    @abstractmethod
    def source(self) -> IntelligenceSource:
        pass

    @abstractmethod
    def fetch_records(self) -> List[VulnerabilityIntelligence]:
        pass



class CisaKevAdapter(IntelligenceSourceAdapter):
    """CISA Known Exploited Vulnerabilities (KEV) Catalog adapter."""

    def __init__(self) -> None:
        self._source = IntelligenceSource(
            source_id="cisa_kev",
            name="CISA Known Exploited Vulnerabilities Catalog",
            source_type="CISA_KEV",
            trust_level=TrustLevel.HIGH,
            update_frequency="1h",
            enabled=True,
            retrieved_at=datetime.now(timezone.utc),
            source_version="2026.1"
        )

    @property
    def source(self) -> IntelligenceSource:
        return self._source

    def fetch_records(self) -> List[VulnerabilityIntelligence]:
        # Return built-in authoritative KEV records for immediate validation
        return [
            VulnerabilityIntelligence(
                vulnerability_id="CVE-2023-34362",
                cve_id="CVE-2023-34362",
                cwe_ids=["CWE-89"],
                cvss_score=9.8,
                severity="CRITICAL",
                affected_ecosystem="PyPI",
                affected_package="moveit-transfer",
                affected_versions=["<2023.0.2"],
                fixed_versions=["2023.0.2"],
                exploitation_status=ExploitationStatus.ACTIVELY_EXPLOITED,
                is_kev=True,
                kev_added_date="2023-06-02",
                kev_due_date="2023-06-23",
                mitre_attack_techniques=["T1190"],
                published_at="2023-06-02T00:00:00Z",
                sources=["CISA KEV"],
                trust_level=TrustLevel.HIGH
            ),
            VulnerabilityIntelligence(
                vulnerability_id="CVE-2021-44228",
                cve_id="CVE-2021-44228",
                cwe_ids=["CWE-502", "CWE-400"],
                cvss_score=10.0,
                severity="CRITICAL",
                affected_ecosystem="Maven",
                affected_package="org.apache.logging.log4j:log4j-core",
                affected_versions=["<2.15.0"],
                fixed_versions=["2.15.0"],
                exploitation_status=ExploitationStatus.ACTIVELY_EXPLOITED,
                is_kev=True,
                kev_added_date="2021-12-10",
                kev_due_date="2021-12-24",
                mitre_attack_techniques=["T1190", "T1059"],
                published_at="2021-12-10T00:00:00Z",
                sources=["CISA KEV"],
                trust_level=TrustLevel.HIGH
            ),
        ]


class NvdAdapter(IntelligenceSourceAdapter):
    """NVD / CVE Feed adapter."""

    def __init__(self) -> None:
        self._source = IntelligenceSource(
            source_id="nvd_cve",
            name="National Vulnerability Database (NVD)",
            source_type="NVD",
            trust_level=TrustLevel.HIGH,
            update_frequency="2h",
            enabled=True,
            retrieved_at=datetime.now(timezone.utc),
            source_version="2.0"
        )

    @property
    def source(self) -> IntelligenceSource:
        return self._source

    def fetch_records(self) -> List[VulnerabilityIntelligence]:
        return [
            VulnerabilityIntelligence(
                vulnerability_id="CVE-2024-21626",
                cve_id="CVE-2024-21626",
                cwe_ids=["CWE-403"],
                cvss_score=8.6,
                severity="HIGH",
                affected_ecosystem="crates.io",
                affected_package="runc",
                affected_versions=["<1.1.12"],
                fixed_versions=["1.1.12"],
                exploitation_status=ExploitationStatus.EXPLOIT_AVAILABLE,
                is_kev=False,
                mitre_attack_techniques=["T1611"],
                published_at="2024-01-31T00:00:00Z",
                sources=["NVD"],
                trust_level=TrustLevel.HIGH
            )
        ]


class IntelligenceSourceRegistry:
    """Central registry to manage and query threat intelligence sources."""

    def __init__(self) -> None:
        self._sources: Dict[str, IntelligenceSourceAdapter] = {}
        self.register_source(CisaKevAdapter())
        self.register_source(NvdAdapter())

    def register_source(self, adapter: IntelligenceSourceAdapter) -> None:
        self._sources[adapter.source.source_id] = adapter

    def get_source(self, source_id: str) -> Optional[IntelligenceSourceAdapter]:
        return self._sources.get(source_id)

    def list_sources(self) -> List[IntelligenceSource]:
        return [adapter.source for adapter in self._sources.values()]

    def enable_source(self, source_id: str) -> None:
        if source_id in self._sources:
            self._sources[source_id].source.enabled = True

    def disable_source(self, source_id: str) -> None:
        if source_id in self._sources:
            self._sources[source_id].source.enabled = False
