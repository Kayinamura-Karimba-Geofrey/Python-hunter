"""Threat Intelligence Domain Models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ExploitationStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    NO_KNOWN_EXPLOIT = "NO_KNOWN_EXPLOIT"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    EXPLOIT_AVAILABLE = "EXPLOIT_AVAILABLE"
    ACTIVELY_EXPLOITED = "ACTIVELY_EXPLOITED"


class ThreatPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class TrustLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class IntelligenceSource:
    source_id: str
    name: str
    source_type: str  # e.g., "NVD", "CISA_KEV", "MITRE_ATTACK", "OSV"
    trust_level: TrustLevel
    update_frequency: str  # e.g., "15m", "1h", "daily"
    enabled: bool = True
    retrieved_at: Optional[datetime] = None
    source_version: str = "1.0.0"


@dataclass
class VulnerabilityIntelligence:
    vulnerability_id: str
    cve_id: Optional[str]
    cwe_ids: List[str]
    cvss_score: float
    severity: str
    affected_ecosystem: str
    affected_package: str
    affected_versions: List[str]
    fixed_versions: List[str]
    exploitation_status: ExploitationStatus
    is_kev: bool = False
    kev_added_date: Optional[str] = None
    kev_due_date: Optional[str] = None
    mitre_attack_techniques: List[str] = field(default_factory=list)
    published_at: Optional[str] = None
    modified_at: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.HIGH


@dataclass
class ThreatActor:
    actor_id: str
    name: str
    aliases: List[str]
    confidence: TrustLevel
    source: str
    description: str = ""


@dataclass
class ThreatCampaign:
    campaign_id: str
    name: str
    targeted_technologies: List[str]
    associated_cves: List[str]
    techniques: List[str]
    confidence: TrustLevel
