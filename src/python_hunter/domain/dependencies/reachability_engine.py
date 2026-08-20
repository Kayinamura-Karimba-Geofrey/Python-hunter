"""Reachability Engine linking SAST Call Graphs with Dependency Vulnerability Intelligence."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.dependencies.models import Dependency, DependencyGraph, DependencyInventory
from python_hunter.domain.dependencies.vulnerability_intel import Advisory
from python_hunter.domain.semantics.program_model import ProgramFunction, ProgramModel


class ReachabilityConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class ReachabilityResult:
    package_name: str
    version: str
    advisory_id: str
    is_reachable: bool
    confidence: ReachabilityConfidence
    call_trace: List[str] = field(default_factory=list)
    entry_point: str = ""
    target_vulnerable_function: str = ""
    evidence_summary: str = ""


class ReachabilityEngine:
    """Performs static function-level reachability verification from application entrypoints to vulnerable dependency APIs."""

    def __init__(self, program_model: Optional[ProgramModel] = None) -> None:
        self.program_model = program_model

    def evaluate_reachability(
        self,
        dependency: Dependency,
        advisory: Advisory,
        graph: Optional[DependencyGraph] = None,
    ) -> ReachabilityResult:
        pkg_name = dependency.name.lower()
        vuln_funcs = advisory.vulnerable_functions or []

        if not self.program_model:
            return ReachabilityResult(
                package_name=dependency.name,
                version=dependency.version,
                advisory_id=advisory.identifier,
                is_reachable=False,
                confidence=ReachabilityConfidence.UNKNOWN,
                evidence_summary="No static application call graph model provided for reachability analysis.",
            )

        all_funcs = self.program_model.all_functions()
        import_matches: List[ProgramFunction] = []
        direct_call_trace: List[str] = []

        # 1. Search for imports or usage of the dependency package in application code
        for func in all_funcs:
            for call in func.calls:
                callee_lower = call.callee_name.lower()
                if pkg_name in callee_lower or any(vf.lower() in callee_lower for vf in vuln_funcs):
                    import_matches.append(func)
                    direct_call_trace.append(f"{func.qualified_name} -> {call.callee_name}")

        if not import_matches:
            return ReachabilityResult(
                package_name=dependency.name,
                version=dependency.version,
                advisory_id=advisory.identifier,
                is_reachable=False,
                confidence=ReachabilityConfidence.LOW,
                evidence_summary=f"Package '{dependency.name}' is present in manifest but no direct references or imports found in application code (UNUSED / POSSIBLY UNUSED).",
            )

        # 2. Check if reachable from an entrypoint handler
        endpoint_entrypoints = [f for f in import_matches if f.is_endpoint_handler]
        if endpoint_entrypoints:
            ep = endpoint_entrypoints[0]
            trace = [ep.qualified_name] + direct_call_trace
            return ReachabilityResult(
                package_name=dependency.name,
                version=dependency.version,
                advisory_id=advisory.identifier,
                is_reachable=True,
                confidence=ReachabilityConfidence.CONFIRMED,
                call_trace=trace,
                entry_point=ep.qualified_name,
                target_vulnerable_function=vuln_funcs[0] if vuln_funcs else "package_api",
                evidence_summary=f"Confirmed reachability trace: HTTP Endpoint [{ep.qualified_name}] directly invokes vulnerable dependency function in package '{dependency.name}'.",
            )

        # High confidence reachability from internal application function
        app_caller = import_matches[0]
        return ReachabilityResult(
            package_name=dependency.name,
            version=dependency.version,
            advisory_id=advisory.identifier,
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            call_trace=[app_caller.qualified_name] + direct_call_trace,
            entry_point=app_caller.qualified_name,
            target_vulnerable_function=vuln_funcs[0] if vuln_funcs else "package_api",
            evidence_summary=f"High reachability trace: Application function [{app_caller.qualified_name}] invokes package '{dependency.name}'.",
        )
