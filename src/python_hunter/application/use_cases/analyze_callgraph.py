"""Application Use Case for Call Graph & Control-Flow Analysis."""

from typing import Any

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.domain.callgraph.engine import CallGraphEngine
from python_hunter.domain.findings.finding import Finding
from python_hunter.rules.callgraph import (
    PYHCall001UnresolvedDynamicCall,
    PYHCall002UnreachableSecurityFunction,
    PYHCall003CircularImportDependency,
    PYHCall004SecuritySinkReachability,
)


class AnalyzeCallGraphUseCase:
    """Orchestrates Symbol Indexing, Call Graph Generation, CFG Construction, Reachability Analysis, and Security Findings."""

    def __init__(self, ast_use_case: AnalyzeASTUseCase | None = None) -> None:
        self.ast_use_case = ast_use_case or AnalyzeASTUseCase()
        self.engine = CallGraphEngine()

        # Rules
        self.rule_unresolved = PYHCall001UnresolvedDynamicCall()
        self.rule_unreachable = PYHCall002UnreachableSecurityFunction()
        self.rule_cycle = PYHCall003CircularImportDependency()
        self.rule_reachability = PYHCall004SecuritySinkReachability()

    def execute(
        self, target_path: str, function_filter: str | None = None
    ) -> dict[str, Any]:
        """Execute call graph and control-flow analysis on target project path."""
        ast_summary = self.ast_use_case.execute(target_path)
        cg_res = self.engine.analyze_documents(ast_summary.documents)

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        # Evaluate unresolved dynamic calls
        for cs in cg_res["call_sites"]:
            f = self.rule_unresolved.evaluate_call_site(cs)
            if f and f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                findings.append(f)

        # Evaluate circular import dependencies
        for scc in cg_res["sccs"]:
            f = self.rule_cycle.evaluate_import_cycle(scc)
            if f and f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                findings.append(f)

        # Evaluate reachability to sinks from entry points
        sinks = ["cursor.execute", "os.system", "subprocess.run", "eval", "open", "requests.get"]
        reachability_results = []
        for ep in cg_res["entry_points"]:
            for sink in sinks:
                reach = self.engine.compute_reachability(ep, sink)
                if reach.is_reachable:
                    reachability_results.append(reach)
                    f = self.rule_reachability.evaluate_reachability(reach)
                    if f and f.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(f.fingerprint)
                        findings.append(f)

        # Filter function if requested
        if function_filter:
            cg_res["symbols"] = {
                q: s for q, s in cg_res["symbols"].items() if function_filter in q
            }

        dot_output = self.engine.export_dot()

        return {
            "target_path": target_path,
            "ast_summary": ast_summary,
            "symbols": cg_res["symbols"],
            "imports": cg_res["imports"],
            "call_sites": cg_res["call_sites"],
            "call_edges": cg_res["call_edges"],
            "entry_points": cg_res["entry_points"],
            "cfgs": cg_res["cfgs"],
            "sccs": cg_res["sccs"],
            "reachability": reachability_results,
            "dot_output": dot_output,
            "findings": findings,
        }
