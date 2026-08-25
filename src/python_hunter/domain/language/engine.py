"""Polyglot Security Analysis Engine orchestrating language detection, analyzer execution, finding normalization, and monorepo discovery."""

import os
from typing import Any, Dict, List, Optional
from python_hunter.domain.analysis.monorepo import CrossLanguageCorrelationEngine, MonorepoDiscoveryEngine
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.language.detector import LanguageDetector, LanguageProfile
from python_hunter.domain.language.models import Language
from python_hunter.domain.language.registry import LanguageRegistry


class PolyglotSecurityAnalysisEngine:
    """Orchestrates detection, analysis, normalization, and correlation across all 13 supported programming languages."""

    def __init__(self, registry: Optional[LanguageRegistry] = None) -> None:
        self.registry = registry or LanguageRegistry()
        self.detector = LanguageDetector()

    def analyze_workspace(
        self,
        workspace_path: str,
        specified_language: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs multi-language security analysis on target workspace."""
        if not os.path.exists(workspace_path):
            raise FileNotFoundError(f"Target workspace path '{workspace_path}' does not exist.")

        # 1. Profile workspace languages and detect sub-projects
        profile: LanguageProfile = self.detector.detect_workspace_languages(workspace_path)
        sub_projects = MonorepoDiscoveryEngine.discover_monorepo_projects(workspace_path)

        # 2. Filter active adapters based on specification or detection
        active_adapters = []
        if specified_language and specified_language.lower() != "all":
            try:
                target_enum = Language(specified_language.lower())
                adapter = self.registry.get_adapter(target_enum)
                if adapter:
                    active_adapters.append(adapter)
            except ValueError:
                pass

        if not active_adapters:
            active_adapters = self.registry.discover_active_adapters(workspace_path)

        # Fallback to Python adapter if no specific adapter detected
        if not active_adapters:
            python_adapter = self.registry.get_adapter(Language.PYTHON)
            if python_adapter:
                active_adapters.append(python_adapter)

        raw_findings: List[Dict[str, Any]] = []
        analyzers_run = []

        # 3. Execute language analyzers
        for adapter in active_adapters:
            try:
                analyzer_findings = adapter.analyze(workspace_path)
                raw_findings.extend(analyzer_findings)
                analyzers_run.append({
                    "language": adapter.language.value,
                    "metadata": adapter.metadata.display_name,
                    "findings_count": len(analyzer_findings)
                })
            except Exception:
                pass

        # 4. Normalize findings to unified Finding model
        normalized_findings: List[Finding] = self._normalize_findings(raw_findings)

        # 5. Perform Cross-Language Correlation
        correlations = CrossLanguageCorrelationEngine.correlate_findings(normalized_findings)

        return {
            "workspace_path": workspace_path,
            "language_profile": {
                "total_files": profile.total_files,
                "total_lines": profile.total_lines,
                "percentages": profile.percentage_by_files,
                "detected_manifests": profile.detected_manifests
            },
            "monorepo_sub_projects_count": len(sub_projects),
            "analyzers_run": analyzers_run,
            "total_raw_findings": len(raw_findings),
            "normalized_findings": normalized_findings,
            "cross_language_correlations": correlations
        }

    def _normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Finding]:
        """Maps raw analyzer dictionaries to standard Python Hunter Finding models."""
        from python_hunter.domain.common.enums import Category, Confidence, Severity
        normalized = []
        seen_keys = set()

        for rf in raw_findings:
            rule_id = rf.get("rule_id", "PYH-GENERIC-001")
            file_path = rf.get("file_path", "unknown")
            line = rf.get("line_number", 1)

            # Deduplication key
            dedup_key = f"{rule_id}:{file_path}:{line}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            sev_str = rf.get("severity", "MEDIUM").upper()
            try:
                sev_enum = Severity(sev_str)
            except ValueError:
                sev_enum = Severity.MEDIUM

            conf_str = rf.get("confidence", "HIGH").upper()
            try:
                conf_enum = Confidence(conf_str)
            except ValueError:
                conf_enum = Confidence.HIGH

            finding = Finding(
                rule_id=rule_id,
                title=rf.get("title", "Security Finding"),
                severity=sev_enum,
                confidence=conf_enum,
                category=Category.CODE_SECURITY,
                description=rf.get("description", rf.get("title", "")),
                file_path=file_path,
                location=None
            )
            normalized.append(finding)
        return normalized
