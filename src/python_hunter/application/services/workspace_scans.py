"""Workspace-level scans: interprocedural SAST, SCA, secrets, and infrastructure-as-code.

Each function walks a local workspace and returns a JSON-serializable result dict. They are
used by SecurityApplicationService and exposed through the REST API and CLI.
"""

import logging
import os
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

SOURCE_EXTENSIONS = (".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb")
DEPENDENCY_MANIFESTS = (
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
)


def _sast_endpoint(func_name: str, line: str) -> bool:
    return "route" in func_name.lower() or "get" in func_name.lower() or "controller" in line.lower()


def _sca_endpoint(func_name: str, line: str) -> bool:
    lowered = line.lower()
    return (
        "route" in func_name.lower()
        or "get" in func_name.lower()
        or "handler" in lowered
        or "request" in lowered
    )


def build_program_model(
    workspace_path: str,
    function_keywords: tuple[str, ...],
    is_endpoint: Callable[[str, str], bool],
) -> Any:
    """Build a lightweight, line-based ProgramModel of functions and call sites."""
    from python_hunter.domain.ir.models import IRLocation
    from python_hunter.domain.language.models import Language
    from python_hunter.domain.semantics.program_model import (
        ProgramCall,
        ProgramFunction,
        ProgramModel,
        ProgramModule,
    )

    model = ProgramModel()
    for root, _, files in os.walk(workspace_path):
        for file in files:
            if not file.endswith(SOURCE_EXTENSIONS):
                continue
            full_path = os.path.join(root, file)
            mod_name = os.path.splitext(file)[0]
            mod = ProgramModule(name=mod_name, file_path=full_path, language=Language.PYTHON)

            with open(full_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            current_fn = None
            for idx, line in enumerate(lines, 1):
                line_str = line.strip()
                if any(kw in line_str for kw in function_keywords):
                    func_name = line_str.split("(")[0]
                    for kw in function_keywords:
                        func_name = func_name.replace(kw, "")
                    func_name = func_name.strip()
                    qual_name = f"{mod_name}.{func_name}"
                    current_fn = ProgramFunction(
                        name=func_name,
                        qualified_name=qual_name,
                        module_name=mod_name,
                        is_endpoint_handler=is_endpoint(func_name, line_str),
                        location=IRLocation(file_path=full_path, start_line=idx),
                    )
                    mod.functions[qual_name] = current_fn
                elif current_fn and "(" in line_str:
                    callee = line_str.split("(")[0].strip().split()[-1] if line_str.split("(")[0].strip() else ""
                    if callee and callee not in ("def", "if", "for", "while", "return"):
                        current_fn.calls.append(
                            ProgramCall(
                                caller_qualified_name=current_fn.qualified_name,
                                callee_name=callee,
                                location=IRLocation(file_path=full_path, start_line=idx),
                            )
                        )

            model.add_module(mod)
    return model


def execute_interprocedural_scan(workspace_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Performs interprocedural SAST analysis across functions, files, modules, and services."""
    from python_hunter.domain.semantics.cache_engine import AnalysisCacheEngine, AnalysisLimits
    from python_hunter.domain.semantics.call_graph_2 import CallGraph2
    from python_hunter.domain.semantics.interprocedural_engine import InterproceduralEngine
    from python_hunter.domain.semantics.rule_engine_2 import RuleEngine2
    from python_hunter.domain.semantics.symbol_table import NameResolver, SymbolTable
    from python_hunter.domain.semantics.taint_registries import (
        SanitizerRegistry,
        TaintSinkRegistry,
        TaintSourceRegistry,
    )

    opts = options or {}
    limits = AnalysisLimits(max_call_depth=opts.get("max_call_depth", 10))
    cache = AnalysisCacheEngine(limits)

    model = build_program_model(workspace_path, ("def ", "function ", "func ", "void "), _sast_endpoint)
    symbol_table = SymbolTable()

    name_resolver = NameResolver(model, symbol_table)
    call_graph = CallGraph2(model, name_resolver)
    call_graph.build()

    engine = InterproceduralEngine(
        model, call_graph, TaintSourceRegistry(), TaintSinkRegistry(), SanitizerRegistry()
    )
    evidences = engine.analyze_workspace()

    rule_engine = RuleEngine2(model, call_graph)
    findings = rule_engine.evaluate_composite_findings(evidences)

    return {
        "status": "COMPLETED",
        "workspace_path": workspace_path,
        "total_nodes": len(call_graph.nodes),
        "total_modules": len(model.modules),
        "total_functions": len(model.all_functions()),
        "total_call_edges": len(call_graph.edges),
        "total_evidences": len(evidences),
        "evidence_count": len(evidences),
        "findings_count": len(findings),
        "findings": findings,
        "cache_stats": cache.get_stats(),
    }


def execute_sca_scan(workspace_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Performs Software Composition Analysis (SCA), Dependency Graphing, Reachability, and License Policy checks."""
    from python_hunter.domain.dependencies.advisory_db import AdvisoryDatabase
    from python_hunter.domain.dependencies.dependency_graph_engine import DependencyGraphEngine
    from python_hunter.domain.dependencies.license_policy import LicensePolicyEngine
    from python_hunter.domain.dependencies.lockfile_parsers import UniversalLockfileParser
    from python_hunter.domain.dependencies.models import DependencyGraph
    from python_hunter.domain.dependencies.reachability_engine import ReachabilityEngine
    from python_hunter.domain.dependencies.remediation_engine import RemediationEngine
    from python_hunter.domain.dependencies.vulnerability_intel import VulnerabilityIntelligence

    db = AdvisoryDatabase()
    intel = VulnerabilityIntelligence([db])
    lic_engine = LicensePolicyEngine()

    model = build_program_model(workspace_path, ("def ", "function ", "func "), _sca_endpoint)
    reach_engine = ReachabilityEngine(model)

    all_deps = []
    manifests = []
    graph = DependencyGraph()

    for root, _, files in os.walk(workspace_path):
        for file in files:
            if file in DEPENDENCY_MANIFESTS:
                full_p = os.path.join(root, file)
                manifests.append(full_p)
                parsed = UniversalLockfileParser.parse_file(full_p)
                all_deps.extend(parsed)
                for dep in parsed:
                    graph.add_dependency(dep)

    analytics = DependencyGraphEngine.analyze_graph(graph)
    vuln_findings = []

    for dep in all_deps:
        for adv in intel.match_advisories(dep.name, dep.version or "0.0.0", dep.ecosystem):
            reach = reach_engine.evaluate_reachability(dep, adv, graph)
            remed = RemediationEngine.generate_recommendation(dep, adv)
            lic_eval = lic_engine.evaluate_dependency(dep)

            paths = graph.get_paths_to(dep.name)
            dep_path = " -> ".join(paths[0]) if paths else dep.name

            vuln_findings.append(
                {
                    "package": dep.name,
                    "version": dep.version or "unpinned",
                    "ecosystem": dep.ecosystem.value,
                    "advisory": adv.identifier,
                    "cve": adv.cve_id,
                    "severity": adv.severity,
                    "cvss": adv.cvss,
                    "affected_versions": adv.affected_versions,
                    "patched_version": adv.patched_versions,
                    "dependency_path": dep_path,
                    "is_direct": dep.is_direct,
                    "reachability": {
                        "is_reachable": reach.is_reachable,
                        "confidence": reach.confidence.value,
                        "evidence": reach.evidence_summary,
                        "call_trace": reach.call_trace,
                    },
                    "license": {
                        "name": lic_eval.license,
                        "policy_action": lic_eval.action.value,
                        "reason": lic_eval.reason,
                    },
                    "remediation": {
                        "action": remed.action,
                        "recommended_version": remed.recommended_version,
                        "breaking_risk": remed.breaking_change_risk,
                        "reason": remed.reason,
                        "guidance": remed.mitigation_guidance,
                    },
                }
            )

    freshness = db.get_freshness_info()

    return {
        "status": "COMPLETED",
        "workspace_path": workspace_path,
        "manifests": manifests,
        "dependency_inventory": {
            "total_dependencies": analytics.total_nodes,
            "direct_count": analytics.direct_count,
            "transitive_count": analytics.transitive_count,
            "max_depth": analytics.max_depth,
            "average_depth": analytics.average_depth,
            "bloat_factor": analytics.bloat_factor,
            "single_points_of_failure": analytics.single_points_of_failure,
        },
        "vulnerability_findings_count": len(vuln_findings),
        "vulnerability_findings": vuln_findings,
        "database_metadata": {
            "version": freshness.database_version,
            "last_update": freshness.last_update,
            "source": freshness.source,
            "total_advisories": freshness.total_advisories,
            "is_stale": freshness.is_stale,
        },
        "dependency_tree": graph.to_tree_str(),
    }


def execute_secrets_scan(
    workspace_path: str, scan_history: bool = False, options: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Scans workspace source code, configuration files, and optionally Git history for credential leaks."""
    from python_hunter.domain.analysis.context import AnalysisContext
    from python_hunter.domain.projects.project import Project
    from python_hunter.domain.secrets.attack_path_secrets import AttackPathSecretMapper
    from python_hunter.domain.secrets.engine import SecretDetectionEngine
    from python_hunter.domain.secrets.git_history_engine import GitHistorySecretScanner

    sec_engine = SecretDetectionEngine()
    context = AnalysisContext(scan_id="scan_sec", project=Project(name="workspace", root_path=workspace_path))
    all_findings = []

    for root, _, files in os.walk(workspace_path):
        if ".git" in root:
            continue
        for file in files:
            full_p = os.path.join(root, file)
            if sec_engine.is_eligible_file(full_p):
                try:
                    with open(full_p, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    all_findings.extend(sec_engine.scan_file(full_p, content, context))
                except Exception:
                    logger.debug("Secret scan skipped %s", full_p, exc_info=True)
                    continue

    historical_findings = []
    if scan_history:
        historical_findings = GitHistorySecretScanner(sec_engine).scan_git_history(workspace_path)

    attack_paths = AttackPathSecretMapper.generate_attack_paths(all_findings)

    formatted_findings = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "file_path": f.file_path,
            "line": f.location.line_start,
            "fingerprint": f.fingerprint,
            "evidence": f.evidence,
            "remediation": f.remediation,
        }
        for f in all_findings
    ]

    return {
        "status": "COMPLETED",
        "workspace_path": workspace_path,
        "active_secrets_count": len(formatted_findings),
        "active_secrets": formatted_findings,
        "historical_secrets_count": len(historical_findings),
        "historical_secrets": [
            {
                "fingerprint": h.fingerprint,
                "secret_type": h.secret_type,
                "detector_id": h.detector_id,
                "first_seen_commit": h.first_seen_commit,
                "first_seen_author": h.first_seen_author,
                "first_seen_date": h.first_seen_date,
                "file_path": h.file_path,
                "current_status": h.current_status,
            }
            for h in historical_findings
        ],
        "attack_paths": [
            {"path_id": ap.path_id, "title": ap.title, "severity": ap.severity, "steps": ap.steps}
            for ap in attack_paths
        ],
    }


def execute_infrastructure_scan(workspace_path: str) -> dict[str, Any]:
    """Scans workspace for Docker, Kubernetes, Helm, Terraform, Cloud, and CI/CD security vulnerabilities."""
    from python_hunter.domain.infrastructure.graph_engine import CrossLayerGraphEngine
    from python_hunter.domain.infrastructure.models import InfrastructureIR
    from python_hunter.domain.infrastructure.rules_engine import InfrastructureSecurityRuleEngine
    from python_hunter.infrastructure.iac.cicd_adapter import CICDAdapter
    from python_hunter.infrastructure.iac.docker_adapter import DockerAdapter
    from python_hunter.infrastructure.iac.k8s_adapter import KubernetesAdapter
    from python_hunter.infrastructure.iac.registry import InfrastructureRegistry
    from python_hunter.infrastructure.iac.terraform_adapter import TerraformAdapter

    registry = InfrastructureRegistry()
    registry.register_adapter(DockerAdapter())
    registry.register_adapter(KubernetesAdapter())
    registry.register_adapter(TerraformAdapter())
    registry.register_adapter(CICDAdapter())

    ir = InfrastructureIR(scan_path=workspace_path)

    for root, _, files in os.walk(workspace_path):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, workspace_path)
            try:
                with open(full_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                registry.process_file(rel_path, content, ir)
            except Exception:
                logger.debug("Infrastructure scan skipped %s", full_path, exc_info=True)

    findings = InfrastructureSecurityRuleEngine().evaluate_ir(ir)

    graph_engine = CrossLayerGraphEngine()
    cross_graph = graph_engine.build_cross_layer_graph(ir)
    attack_paths = graph_engine.trace_cross_layer_attack_paths(cross_graph)

    formatted_findings = [
        {
            "id": f"iac-find-{idx + 1}",
            "rule_id": f.rule_id,
            "title": f.rule_name,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "evidence": f.evidence,
            "description": f.description,
            "remediation": f.remediation,
        }
        for idx, f in enumerate(findings)
    ]

    resources_formatted = [
        {
            "id": r.id,
            "name": r.name,
            "type": r.type.value,
            "provider": r.provider,
            "file_path": r.file_path,
            "line": r.line,
            "is_publicly_exposed": r.is_publicly_exposed,
            "is_privileged": r.is_privileged,
            "runs_as_root": r.runs_as_root,
            "has_encryption_enabled": r.has_encryption_enabled,
        }
        for r in ir.resources
    ]

    return {
        "status": "COMPLETED",
        "workspace_path": workspace_path,
        "resources_count": len(resources_formatted),
        "resources": resources_formatted,
        "findings_count": len(formatted_findings),
        "findings": formatted_findings,
        "attack_paths_count": len(attack_paths),
        "attack_paths": attack_paths,
    }
