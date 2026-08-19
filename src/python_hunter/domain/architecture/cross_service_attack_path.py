"""Cross-Service Attack Path Engine."""

from dataclasses import dataclass, field
from python_hunter.domain.architecture.service_models import Service, TrustBoundary


@dataclass
class CrossServiceAttackPath:
    """Represents an end-to-end multi-service attack path."""

    path_id: str
    entry_point: str
    steps: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    exploitability: str = "HIGH"
    description: str = ""


class CrossServiceAttackPathEngine:
    """Traces multi-service attack paths across gateway boundaries, internal microservices, and databases."""

    def build_attack_paths(self, services: list[Service]) -> list[CrossServiceAttackPath]:
        paths = []

        public_services = [s for s in services if s.trust_boundary in (TrustBoundary.PUBLIC_API, TrustBoundary.INTERNET)]
        internal_services = [s for s in services if s.trust_boundary == TrustBoundary.INTERNAL_SERVICE]

        # Trace Internet -> Public Gateway -> Internal Service -> DB
        for pub in public_services:
            for call in pub.api_calls:
                for int_s in internal_services:
                    if int_s.service_id in call.target_url or int_s.name in call.target_url:
                        paths.append(
                            CrossServiceAttackPath(
                                path_id=f"PATH-{pub.service_id}-{int_s.service_id}",
                                entry_point=f"Public Service: {pub.name}",
                                steps=[
                                    f"Internet -> {pub.name}",
                                    f"{pub.name} -> Outbound API Call ({call.http_method} {call.target_url})",
                                    f"Internal Service -> {int_s.name}",
                                    f"{int_s.name} -> Database Sink / Sensitive Asset",
                                ],
                                risk_score=8.5,
                                exploitability="HIGH",
                                description=f"Attacker input at {pub.name} crosses trust boundary into internal service {int_s.name}.",
                            )
                        )

        return paths
